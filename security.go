package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"os"
	"strconv"

	"strings"

	"errors"

	"github.com/go-zoo/bone"
	"github.com/nerdynz/datastore"
	uuid "github.com/satori/go.uuid"
)

const (
	// NoAuth value for no auth on route
	NoAuth = "none"
	// Redirect value will force the router to redirect to the /Login route
	Redirect = "redirect"
	// Disallow will return a 403 Forbbiden response
	Disallow = "disallow"

	// // Redis as the storage location for checking login valid
	// Redis = "Redis"
	// // Database as the storage location for checking login valid
	// Database = "Database"
)

type SessionInfo struct {
	User       *SessionUser `json:"user"`
	Token      string       `json:"token"`
	Expiration time.Time    `json:"expiration"`
	CacheToken string       `json:"cache"`
}

type SessionUser struct {
	ID         int    `db:"id" json:"ID"`
	Name       string `db:"name" json:"Name"`
	Email      string `db:"email" json:"Email"`
	Password   string `db:"password" json:"-"`
	Role       string `db:"role" json:"Role"`
	SiteID     int    `db:"site_id" json:"SiteID"`
	CacheToken string `json:"CacheToken"`
	TableName  string `json:"TableName"`
}

type Padlock struct {
	Req          *http.Request
	Store        *datastore.Datastore
	loggedInUser *SessionUser
	token        string
	siteID       int
}

type UserSessionToken struct {
	CacheToken   string    `db:"cache_token"`
	TableName    string    `db:"table_name"`
	RecordID     int       `db:"record_id"`
	ExpiryDate   time.Time `db:"expiry_date"`
	DateCreated  time.Time `db:"date_created"`
	DateModified time.Time `db:"date_modified"`
}

type UserSessionTokens []*UserSessionToken

// TODO REFACTOR... Bad naming
// func NewWithContext(ctx *flow.Context) *Padlock {
// 	padlock := &Padlock{}
// 	padlock.Req = ctx.Req
// 	padlock.Store = ctx.Store
// 	return padlock
// }

func New(req *http.Request, store *datastore.Datastore) *Padlock {
	padlock := &Padlock{}
	padlock.Req = req
	padlock.Store = store
	return padlock
}

// NewWithToken - doesnt rely on request, current usecase is websockets... im sure there are more
func NewWithToken(token string, store *datastore.Datastore) *Padlock {
	padlock := &Padlock{}
	padlock.token = token
	padlock.Store = store
	return padlock
}

func (padlock *Padlock) LoginReturningInfo(email string, password string, tableName string) (*SessionInfo, error) {
	return padlock.LoginReturningInfoEx(-1, email, password, tableName)
}

// BypassLoginReturningCookie gets a login cookie without needing user name and password,
// for example user has just signed up, meaning we of course know they are valid
// or we have logged in via facebook oauth
// THIS SHOULD NOT BE USED FROM A REQUEST VARIABLE i.e. pass ID and login, we NEED TO CHECK THERE PASSWORD or FACEBOOK AUTH ETC
func (padlock *Padlock) BypassLoginReturningCookie(id int, tableName string) (*http.Cookie, error) {
	tokenName := getSessionUserCookieName()
	sessionInfo, err := padlock.LoginReturningInfoEx(id, "", "", tableName) // same process / different format
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{Name: tokenName, Value: sessionInfo.Token, Expires: sessionInfo.Expiration, Path: "/", Domain: padlock.Req.Host}
	return cookie, nil
}

func (padlock *Padlock) LoginReturningCookie(email string, password string, tableName string) (*http.Cookie, error) {
	tokenName := getSessionUserCookieName()

	sessionInfo, err := padlock.LoginReturningInfo(email, password, tableName) // same process / different format
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{Name: tokenName, Value: sessionInfo.Token, Expires: sessionInfo.Expiration, Path: "/", Domain: padlock.Req.Host}
	return cookie, nil
}

func (padlock *Padlock) LoginReturningInfoEx(id int, email string, password string, tableName string) (*SessionInfo, error) {
	info := &SessionInfo{}
	user := &SessionUser{}

	tableName = strings.ToLower(tableName)

	// valid names for table
	tableIDName := ""
	if tableName == "administrator" {
		tableIDName = "administrator_id"
	} else if tableName == "user" {
		tableIDName = "user_id"
	} else if tableName == "member" {
		tableIDName = "member_id"
	} else if tableName == "person" {
		tableIDName = "person_id"
	} else {
		return nil, errors.New("Invalid table name for security SessionUser table")
	}

	ex := ""
	if padlock.Store.Settings.IsSiteBound {
		ex += ",site_id"
	}
	sql := padlock.Store.DB.
		Select(tableIDName + " as id, name, email, password, role" + ex).
		From(tableName)

	if id > 0 {
		sql.Where(tableIDName+" = $1", id) // id doesn't need a password as we already know who they are
	} else {
		sql.Where("LOWER(email) = LOWER($1) and password = $2", email, password)
	}
	sql.Limit(1)
	err := sql.QueryStruct(user)

	if err != nil {
		return nil, errors.New("Login Failed")
	}

	uuid := uuid.NewV4().String() //key for redis or something needs to be part of the json package
	user.CacheToken = uuid
	user.TableName = tableName
	// save the new sessionToken into the database so it can be cleared from the cache later if the user gets deleted

	jsonUser, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	info.Token = Encrypt(string(jsonUser))

	expirationInDays := 30 //default
	expirationDayEnv := os.Getenv("SECURITY_USER_TOKEN_EXPIRATION")
	if expirationDayEnv != "" {
		expirationInDays, _ = strconv.Atoi(expirationDayEnv) // if it can't convert then just use the default
	}

	duration := time.Duration(expirationInDays) * (24 * time.Hour)
	expiration := time.Now().Add(duration)
	info.Expiration = expiration
	info.CacheToken = user.CacheToken

	// // we need to expire any exist LOGOUT EVERYWHERE
	// var expireTokens UserSessionTokens
	// err = padlock.Store.DB.
	// 	Select("*").
	// 	From("usersession_token").
	// 	Where("tablename = $1 and recordID = $2", tableName, user.ID).
	// 	QueryStructs(&expireTokens)

	// for _, tok := range expireTokens {
	// 	tok.CacheToken
	// }

	_, err = padlock.Store.DB.
		InsertInto("usersession_token").
		Columns("cache_token", "table_name", "record_id", "expiry_date", "date_created", "date_modified").
		Values(user.CacheToken, tableName, user.ID, expiration, time.Now(), time.Now()).
		Exec()

	if err != nil {
		return nil, err
	}

	status := padlock.Store.Cache.Set(user.CacheToken, string(jsonUser), duration)

	if status.Err() != nil {
		return nil, err
	}

	info.User = user
	return info, nil
}

func (padlock *Padlock) SiteID() int {
	// optimise
	if padlock.siteID > 0 {
		return padlock.siteID
	}
	if padlock.Store.Settings.IsSiteBound {
		if padlock.IsLoggedIn() {
			user, _ := padlock.LoggedInUser()
			if user.SiteID < 1 {
				panic("Invalid siteID")
			}
			padlock.siteID = user.SiteID
			return user.SiteID
		}
		panic("SiteID accessed without being logged in")
	}
	panic("IS_SITE_BOUND not set")
}

func (padlock *Padlock) IsLoggedIn() bool {
	user, _ := padlock.LoggedInUser()
	return user != nil
}

func (padlock *Padlock) IsLoggedInAs(tableName string) bool {
	user, _ := padlock.LoggedInUser()
	if user == nil {
		return false
	}
	return user.TableName == tableName
}

func (padlock *Padlock) Logout() {
	user, _ := padlock.LoggedInUser()
	padlock.Store.Cache.Set(user.CacheToken, "", 1*time.Second)

}

func (padlock *Padlock) UpdateAuthToken(tok string) {
	padlock.token = tok
}

func (padlock *Padlock) GetAuthToken() (string, error) {
	// check for basic authentication header
	authToken := padlock.token // we already have it

	// check the request header
	if authToken == "" {
		authHeader := padlock.Req.Header.Get("Authorization")
		if authHeader != "" {
			// potentially found a token in the Authorization header
			authTokenBits := strings.Split(authHeader, "Basic ")
			if len(authTokenBits) == 1 {
				return "", errors.New("invalid auth token")
			}
			authToken = authTokenBits[1]
		}
	}

	// we still haven't found the authtoken so try checking a cookie
	if authToken == "" {
		authToken = padlock.Req.URL.Query().Get("authtoken")
	}
	// we still haven't got it so check router
	if authToken == "" {
		authToken = bone.GetValue(padlock.Req, "authtoken")
	}
	// we still haven't found the authtoken so try checking a cookie
	if authToken == "" {
		tokenName := getSessionUserCookieName()
		cookie, err := padlock.Req.Cookie(tokenName)
		if err != nil {
			if err.Error() == "http: named cookie not present" {
				return "", errors.New("no auth details found in the request")
			}
			return "", err
		}
		authToken = cookie.Value
	}
	return authToken, nil
}

func (padlock *Padlock) LoggedInUser() (*SessionUser, error) {
	// optimisation
	if padlock.loggedInUser != nil {
		return padlock.loggedInUser, nil
	}

	authToken, err := padlock.GetAuthToken()

	user := &SessionUser{}

	//Decrypt the authToken
	val, err := Decrypt(authToken)
	if err != nil {
		return nil, err
	}

	// grab the resulting json object into a SessionUser struct
	err = json.Unmarshal([]byte(val), user)
	// log.Info("user is good?", user)
	if err != nil {
		return nil, err
	}

	if user.ID == 0 {
		return nil, errors.New("user doesn't exist")
	}

	if user.CacheToken == "" {
		return nil, errors.New("invalid token")
	}

	cachedUser := &SessionUser{}
	serializedUser, err := padlock.Store.Cache.Get(user.CacheToken).Result()

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(serializedUser), cachedUser)

	if err != nil {
		return nil, err
	}

	// awesome - you are logged in
	if cachedUser.Email == user.Email && cachedUser.Password == user.Password && cachedUser.ID == user.ID {
		padlock.loggedInUser = cachedUser
		padlock.siteID = cachedUser.SiteID
		return cachedUser, nil
	}
	return nil, errors.New("user didnt match cache... something funky here.")
}

func (padlock *Padlock) CheckLogin() (bool, error) {
	_, err := padlock.LoggedInUser()
	if err == nil {
		return true, nil
	}
	return false, err
}

// encrypt string to base64 crypto using AES
func Encrypt(text string) string {
	key := os.Getenv("SECURITY_ENCRYPTION_KEY")
	if key == "" {
		panic("SECURITY_ENCRYPTION_KEY not set")
	}

	// key := []byte(keyText)
	plaintext := []byte(text)
	cypherKey := []byte(key)

	block, err := aes.NewCipher(cypherKey)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func Decrypt(cryptoText string) (string, error) {
	key := os.Getenv("SECURITY_ENCRYPTION_KEY")
	cypherKey := []byte(key)
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
	block, err := aes.NewCipher(cypherKey)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
}

func GenerateRandomKey(length int) []byte {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}

func getSessionUserCookieName() string {
	tokenName := os.Getenv("SECURITY_USER_COOKIE_NAME")
	if tokenName == "" {
		tokenName = "user_cookie"
	}
	return tokenName
}
