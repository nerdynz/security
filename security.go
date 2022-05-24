package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	mathRand "math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/oklog/ulid"

	"os"

	"strings"

	"errors"
)

const (
	// NoAuth value for no auth on route
	NoAuth = "none"
	// Redirect value will force the router to redirect to the /Login route
	Redirect = "redirect"
	// Disallow will return a 403 Forbbiden response
	Disallow           = "disallow"
	TempNoAuthDisallow = "none"

	// // Redis as the storage location for checking login valid
	// Redis = "Redis"
	// // Database as the storage location for checking login valid
	// Database = "Database"
)

type SessionLoginAttempt struct {
	Email    string `db:"email" json:"email,omitempty"`
	Password string `db:"password" json:"password,omitempty"`
	SiteULID string `db:"site_ulid" json:"siteULID,omitempty"`
}

func LoginAttemptFromRequest(req *http.Request) (*SessionLoginAttempt, error) {
	loginAttempt := &SessionLoginAttempt{}
	if strings.Contains(req.Header.Get("Content-Type"), "application/json") {
		// working with json
		decoder := json.NewDecoder(req.Body)
		err := decoder.Decode(loginAttempt)
		if err != nil {
			return nil, err
		}
		return loginAttempt, nil
	}
	return nil, errors.New("unable to parse login attempt from that content type")
}

type SessionInfo struct {
	User       *SessionUser `json:"user"`
	Token      string       `json:"token"`
	Expiration time.Time    `json:"expiration"`
	Sites      []*Site      `json:"sites"`
}

type SessionUser struct {
	Username string `db:"username" json:"username,omitempty"`
	Name     string `db:"name" json:"name"`
	Email    string `db:"email" json:"email"`
	Password string `db:"password" json:"-"`
	Role     string `db:"role" json:"role"`
	Picture  string `db:"picture" json:"picture"`
	Initials string `db:"initials" json:"initials"`
	ULID     string `db:"ulid" json:"ulid,omitempty"`
	SiteULID string `db:"site_ulid" json:"siteULID,omitempty"`
}

type Site struct {
	Name     string `db:"name" json:"name"`
	SiteULID string `db:"site_ulid" json:"siteULID,omitempty"`
}

type NotAuthorizedUser struct {
	Username string `db:"username"`
	Email    string `db:"email"`
	Password string `db:"password"`
	Role     string `db:"role"`
	ULID     string `db:"ulid"`
	SiteULID string `db:"site_ulid"`
}

type Padlock struct {
	ctx      context.Context
	req      *http.Request
	settings Settings
	key      Key
	// Cache        Cache
	token        string
	siteID       int
	loggedInUser *SessionUser
	authToken    string
}

// type Cache interface {
// 	GetCacheBytes(key string) ([]byte, error)
// 	GetCacheValue(key string) (string, error)
// 	SetCacheValue(key string, value interface{}, duration time.Duration) (string, error)
// }

// type UserSessionToken struct {
// 	CacheToken   string    `db:"cache_token"`
// 	TableName    string    `db:"table_name"`
// 	RecordID     int       `db:"record_id"`
// 	ExpiryDate   time.Time `db:"expiry_date"`
// 	DateCreated  time.Time `db:"date_created"`
// 	DateModified time.Time `db:"date_modified"`
// }

// type UserSessionTokens []*UserSessionToken

// TODO REFACTOR... Bad naming
// func NewWithContext(ctx *flow.Context) *Padlock {
// 	padlock := &Padlock{}
// 	padlock.req = ctx.Req
// 	padlock.Store = ctx.Store
// 	return padlock
// }

func New(req *http.Request, settings Settings, key Key) *Padlock {
	padlock := &Padlock{}
	padlock.req = req
	padlock.settings = settings
	padlock.key = key
	return padlock
}

func NewFromContext(ctx context.Context, key Key) *Padlock {
	padlock := &Padlock{}
	padlock.ctx = ctx
	// padlock.settings = settings
	padlock.key = key
	return padlock
}

// NewWithToken - doesnt rely on request, current usecase is websockets... im sure there are more
// func NewWithToken(token string) *Padlock {
// 	padlock := &Padlock{}
// 	padlock.token = token
// 	// padlock.Store = store
// 	return padlock
// }

// GetCachedValue put other relevant stuff against the user here, such as an authtoken etc
func (padlock *Padlock) GetCachedValue(key string) ([]byte, error) {
	_, authToken, err := padlock.LoggedInUser()
	if err != nil {
		return nil, err
	}
	return padlock.key.GetCacheValue(authToken, key)
}

// SetCachedValue grab and cast other stuff to what you need from a user
func (padlock *Padlock) SetCachedValue(key string, value []byte, duration time.Duration) error {
	_, authToken, err := padlock.LoggedInUser()
	if err != nil {
		return err
	}
	return padlock.key.SetCacheValue(authToken, key, value, duration)
}

// BypassLoginReturningCookie gets a login cookie without needing user name and password,
// for example user has just signed up, meaning we of course know they are valid
// or we have logged in via facebook oauth
// THIS SHOULD NOT BE USED FROM A REQUEST VARIABLE i.e. pass ID and login, we NEED TO CHECK THERE PASSWORD or FACEBOOK AUTH ETC
func (padlock *Padlock) BypassLoginReturningCookie(ulid string) (*http.Cookie, error) {
	tokenName := getSessionUserCookieName(padlock.settings)
	sessionInfo, err := padlock.LoginWithULID(ulid) // same process / different format
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{Name: tokenName, Value: sessionInfo.Token, Expires: sessionInfo.Expiration, Path: "/", Domain: padlock.req.Host}
	return cookie, nil
}

func (padlock *Padlock) LoginReturningCookie(email string, password string) (*http.Cookie, error) {
	tokenName := getSessionUserCookieName(padlock.settings)

	sessionInfo, err := padlock.LoginReturningInfo(email, password) // same process / different format
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{Name: tokenName, Value: sessionInfo.Token, Expires: sessionInfo.Expiration, Path: "/", Domain: padlock.req.Host}
	return cookie, nil
}

func (padlock *Padlock) LoginFromRequest(req *http.Request) (*SessionInfo, error) {
	attempt, err := LoginAttemptFromRequest(req)
	if err != nil {
		return nil, err
	}
	return padlock.loginDefaultDuration("", attempt.Email, attempt.Password, attempt.SiteULID)
}

func (padlock *Padlock) LoginReturningInfo(email string, password string) (*SessionInfo, error) {
	return padlock.loginDefaultDuration("", email, password, "")
}

// LoginToSiteReturningInfo for multi tenant users, we pass a specific site ID
func (padlock *Padlock) LoginToSiteReturningInfo(email string, password string, siteULID string) (*SessionInfo, error) {
	return padlock.loginDefaultDuration("", email, password, siteULID)
}

func (padlock *Padlock) LoginWithULID(ulid string) (*SessionInfo, error) {
	return padlock.loginDefaultDuration(ulid, "", "", "")
}

func (padlock *Padlock) loginDefaultDuration(ulid string, email string, password string, optionalSiteULID string) (*SessionInfo, error) {
	expirationInDays := 30 //default
	expirationDayEnv := padlock.settings.Get("SECURITY_USER_TOKEN_EXPIRATION")
	if expirationDayEnv != "" {
		expirationInDays, _ = strconv.Atoi(expirationDayEnv) // if it can't convert then just use the default
	}
	duration := time.Duration(expirationInDays) * (24 * time.Hour)
	return padlock.login(ulid, email, password, optionalSiteULID, duration)
}

//
func (padlock *Padlock) login(ulid string, email string, password string, optionalSiteULID string, duration time.Duration) (*SessionInfo, error) {
	if password == "" && ulid == "" {
		return nil, errors.New("password must be provided")
	}

	fakeUser := &NotAuthorizedUser{}
	fakeUser.Email = email
	fakeUser.Password = password
	fakeUser.SiteULID = optionalSiteULID

	info := &SessionInfo{}

	user, err := padlock.key.DoLogin(fakeUser)
	if err != nil {
		return nil, err
	}

	if user.Email == "" && user.Username == "" && ulid == "" {
		return nil, errors.New("Email must be provided")
	}

	// var duration time.Duration
	// if token == nil {
	// 	expirationInDays := 30 //default
	// 	expirationDayEnv := os.Getenv("SECURITY_USER_TOKEN_EXPIRATION")
	// 	if expirationDayEnv != "" {
	// 		expirationInDays, _ = strconv.Atoi(expirationDayEnv) // if it can't convert then just use the default
	// 	}

	// 	duration = time.Duration(expirationInDays) * (24 * time.Hour)
	// } else {
	// 	duration = time.Now().Sub(token.Expiry)
	// }

	info.Expiration = time.Now().Add(duration)
	info.User = user
	if user.ULID != "" {
		info.Token = Encrypt(user.ULID)
	}
	if info.Token == "" {
		return nil, errors.New("Invalid token")
	}

	// _, err = padlock.Store.DB.
	// 	InsertInto("usersession_token").
	// 	Columns("cache_token", "table_name", "record_id", "expiry_date", "date_created", "date_modified").
	// 	Values(user.CacheToken, tableName, user.ID, expiration, time.Now(), time.Now()).
	// 	Exec()

	// if err != nil {
	// 	return nil, err
	// }

	err = padlock.key.SetLogin(info.Token, info, duration)
	if err != nil {
		return nil, err
	}

	padlock.cacheLogin(info.User, info.Token)

	// make sure we are fully logged in then also check for other sites we may belong to
	sites, err := padlock.key.GetSites(info.User.Email) // dont care about this error
	if err != nil {
		return nil, err
	}
	info.Sites = sites

	return info, nil
}

func (padlock *Padlock) SiteULID() (string, error) {
	// optimise
	if padlock.loggedInUser != nil {
		return padlock.loggedInUser.SiteULID, nil
	}
	if padlock.IsLoggedIn() {
		user, _, _ := padlock.LoggedInUser()
		if user.SiteULID == "" {
			return "", errors.New("Invalid user site_ulid")
		}
		return user.SiteULID, nil
	}
	return "", errors.New("Site ulid accessed without being logged in")
}

func (padlock *Padlock) IsLoggedIn() bool {
	user, _, _ := padlock.LoggedInUser()
	return user != nil
}

func (padlock *Padlock) IsLoggedInAs(userType string) bool {
	user, _, _ := padlock.LoggedInUser()
	if user == nil {
		return false
	}
	return user.Role == userType
}

func (padlock *Padlock) ExpireLoginToken(token string) (bool, error) {
	err := padlock.key.ExpireLoggedInUser(token)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (padlock *Padlock) Logout() (bool, error) {
	_, token, err := padlock.LoggedInUser()
	if err != nil {
		return false, err
	}
	return padlock.ExpireLoginToken(token)
}

func (padlock *Padlock) UpdateAuthToken(tok string) {
	padlock.token = tok
}

func (padlock *Padlock) GetAuthToken() (authToken string, err error) {
	authToken = padlock.token // we already have it

	// check for basic authentication header
	authHeader := ""
	if padlock.ctx != nil {
		authHeader = padlock.ctx.Value("authorization").(string)
	}
	if padlock.req != nil {
		authHeader = padlock.req.Header.Get("Authorization")
	}
	if authHeader != "" {
		// potentially found a token in the Authorization header
		return tokenFromAuthorizationHeader(authHeader)
	}

	// token is passed directly
	if padlock.req != nil {
		// check the request header

		// we still haven't found the authtoken so try checking a cookie
		if authToken == "" {
			authToken = padlock.req.URL.Query().Get("authtoken")
		}
		// we still haven't got it so check via key interface
		if authToken == "" {
			authToken, err = padlock.key.GetAuthToken(padlock.req)
			if err != nil {
				return "", err
			}
		}
		// we still haven't found the authtoken so try checking a cookie
		if authToken == "" {
			tokenName := getSessionUserCookieName(padlock.settings)
			cookie, err := padlock.req.Cookie(tokenName)
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

	return "", errors.New("Unauthorised")
}

func (padlock *Padlock) LoggedInUserULID() (string, error) {
	user, _, err := padlock.LoggedInUser()
	if err != nil {
		return "", err
	}
	return user.ULID, nil
}

func (padlock *Padlock) cacheLogin(user *SessionUser, authToken string) {
	padlock.loggedInUser = user
	padlock.authToken = authToken
}

func (padlock *Padlock) LoggedInUser() (user *SessionUser, authToken string, err error) {
	// optimisation
	if padlock.loggedInUser != nil {
		return padlock.loggedInUser, padlock.authToken, nil
	}
	authToken, err = padlock.GetAuthToken()
	if err != nil {
		return nil, "", err
	}

	user = &SessionUser{}
	info, err := padlock.key.GetLogin(authToken)
	if err != nil {
		return nil, "", err
	}

	padlock.cacheLogin(info.User, authToken)
	return info.User, authToken, nil
}

func (padlock *Padlock) CheckLogin() (bool, error) {
	_, _, err := padlock.LoggedInUser()
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
	ciphertext, _ := base64Decrypt(cryptoText)
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

func base64Decrypt(b64 string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(b64)
}

func Base64Encode(b64 []byte) string {
	return base64.URLEncoding.EncodeToString(b64)
}

func GenerateRandomKey(length int) []byte {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}

// ULID - not concurrent
func ULID() string {
	t := time.Now()
	entropy := mathRand.New(mathRand.NewSource(t.UnixNano()))
	u := ulid.MustNew(ulid.Timestamp(t), entropy)
	return u.String()
}

func getSessionUserCookieName(settings Settings) string {
	tokenName := ""
	if settings != nil {
		tokenName = settings.Get("SECURITY_USER_COOKIE_NAME")
	}
	if tokenName == "" {
		tokenName = "user_cookie"
	}
	return tokenName
}

func (padlock *Padlock) Sites(email string) ([]*Site, error) {
	return padlock.key.GetSites(email)
}

type Settings interface {
	Get(key string) string
	GetBool(key string) bool
	IsProduction() bool
}

type Key interface {
	GetLogin(cacheKey string) (*SessionInfo, error)
	SetLogin(cacheKey string, value *SessionInfo, duration time.Duration) error
	ExpireLoggedInUser(key string) error
	DoLogin(notLoggedInUser *NotAuthorizedUser) (*SessionUser, error)
	SetCacheValue(userkey string, key string, value []byte, duration time.Duration) error
	GetCacheValue(userkey string, key string) ([]byte, error)
	GetAuthToken(*http.Request) (string, error)
	GetSites(email string) ([]*Site, error)
}

type BasicKey struct {
}

func (k *BasicKey) GetAuthToken(req *http.Request) (string, error) {
	// there are some basic checks built in so this is an extension
	return "", nil
}

func (k *BasicKey) GetLoggedInUser(authToken string) (*SessionUser, error) {
	u := &SessionUser{}
	blob, err := k.GetCacheValue("", authToken)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(blob, u)
	return u, err
}

func (k *BasicKey) SetLoggedInUser(authToken string, user *SessionUser, duration time.Duration) error {
	ubts, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return k.SetCacheValue("", authToken, ubts, duration) // we dont need to set a userkey for the login because this is our user key
}

func (k *BasicKey) ExpireLoggedInUser(key string) error {
	dur := 1 * time.Second
	return k.SetCacheValue("", key, nil, dur) // cya
}

func (k *BasicKey) doLogin(notLoggedInUser *SessionUser) (*SessionUser, error) {
	return nil, errors.New("You need to implement some database or other logic to get a user from persistant storage")
}
func (k *BasicKey) SetCacheValue(userkey string, key string, value interface{}, duration time.Duration) error {
	return errors.New("You need to implement a cache setter here. Perhaps redis :_")
}
func (k *BasicKey) GetCacheValue(userkey string, key string) ([]byte, error) {
	return nil, errors.New("You need to implement a cache getter here. Perhaps redis :_")
}

func tokenFromAuthorizationHeader(authHeader string) (string, error) {
	authTokenBits := strings.Split(authHeader, "Basic ")
	if len(authTokenBits) == 1 {
		return "", errors.New("invalid auth token")
	}
	return authTokenBits[1], nil
}
