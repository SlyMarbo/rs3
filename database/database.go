package database

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/SlyMarbo/rss"
	"io"
	sec "rs3/security"
	"sync"
	"time"
)

var db *database

func init() {
	db = newDatabase()
}

type database struct {
	Users      map[string]*User     //uid -> User
	Salts      map[string]*sec.Salt //email -> Salt
	Emails     map[string]struct{}  //email -> null (for email existence check)
	Algorithms map[string]*CacheItem
	*sync.RWMutex
}

type CacheItem struct {
	Path string
	Gzip bool
}

// func NewDatabase() *Database
func newDatabase() *database {
	db := database{
		make(map[string]*User),
		make(map[string]*sec.Salt),
		make(map[string]struct{}),
		make(map[string]*CacheItem),
		new(sync.RWMutex),
	}
	return &db
}

type User struct {
	Uid      []byte
	Pswrd    []byte
	Salt     *sec.Salt
	Nick     string
	Cookies  CookieJar
	Feeds    []*rss.Feed
	FeedUrls []string
	mutex    *sync.RWMutex
}

func newUser(uid, pwd []byte, salt *sec.Salt, nick string) *User {
	user := User{
		uid,
		pwd,
		salt,
		nick,
		make(CookieJar, 0),
		make([]*rss.Feed, 0),
		make([]string, 0),
		new(sync.RWMutex),
	}
	return &user
}

//256 rand number 
type Cookie struct {
	Exp     time.Time
	Replace time.Time
	Cookie  string
}

type CookieJar []*Cookie

func newCookie() (*Cookie, error) {
	b := make([]byte, 32) //256 bits
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return &Cookie{}, err
	}

	cookie := Cookie{
		time.Now().Add(7 * 24 * time.Hour),
		time.Now().Add(14 * 24 * time.Hour),
		fmt.Sprintf("%16x", string(b)),
	}
	return &cookie, nil
}

func Salt(email string) *sec.Salt {
	return db.Salts[email]
}

func Gzip(str string) *CacheItem {
	item, ok := db.Algorithms[str]
	if !ok {
		return nil
	}
	return item
}

//AddUser creates a new user and adds it to the database. It establishes that both the user
//does not exist and that their email is not in use
func AddUser(uid, pwd []byte, salt *sec.Salt, nick, email string) error {
	db.RLock()
	if _, ok := db.Users[UidToString(uid)]; ok {
		db.RUnlock()
		return new(UserAlreadyExists)
	}
	if _, ok := db.Emails[string(uid)]; ok {
		db.RUnlock()
		return new(EmailAlreadyExists)
	}
	db.RUnlock()
	db.Lock()
	defer db.Unlock()
	user := newUser(uid, pwd, salt, nick)
	db.Users[UidToString(uid)] = user
	db.Salts[email] = salt
	db.Emails[email] = *new(struct{})
	return nil
}

//Delete user removes a user from the database provided they exist in the system
func DeleteUser(uid []byte) error {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.Users[UidToString(uid)]; !ok {
		return new(UserDoesNotExist)
	}
	delete(db.Users, UidToString(uid))
	return nil
}

//Exists confirms whether or not a user exists in the system
func Exists(uid []byte) bool {
	db.RLock()
	defer db.RUnlock()
	_, ok := db.Users[UidToString(uid)]
	return ok
}

//Authenticate checks that the userID and password match.
func Authenticate(uid, pswd []byte) bool {
	db.RLock()
	defer db.RUnlock()
	user, ok := db.Users[UidToString(uid)]
	if !ok {
		return false
	} else {
		user.mutex.RLock()
		defer user.mutex.RUnlock()
		return (bytes.Compare(user.Pswrd, pswd) == 0)
	}
}

//Login logs a user into the system, returning the cookie string
//Authenticates the user first
//if user already has a valid cookie, returns that cookie as opposed to creating one
func Login(uid, pswd []byte) (string, time.Time, error) {
	db.RLock()
	defer db.RUnlock()
	user, ok := db.Users[UidToString(uid)]
	if !ok {
		return "", time.Now(), new(UserDoesNotExist)
	}
	if !Authenticate(uid, pswd) {
		return "", time.Now(), new(AuthenticationError)
	}
	if len(user.Cookies) != 0 {
		for i := 0; i < len(user.Cookies); i++ {
			if user.Cookies[i].Exp.After(time.Now()) {
				return user.Cookies[i].Cookie, user.Cookies[i].Exp, nil
			}
		}
		c, err := newCookie()
		if err != nil {
			return "", time.Now(), err
		}
		user.Cookies = append(user.Cookies, c)
		return c.Cookie, c.Exp, nil
	} else {
		c, err := newCookie()
		if err != nil {
			return "", time.Now(), err
		}
		user.Cookies = append(user.Cookies, c)
		return user.Cookies[0].Cookie, user.Cookies[0].Exp, nil
	}
}

//Validate checks the cookie.
func Validate(cookie string, uid []byte) (bool, string, time.Time) {
	db.RLock()
	defer db.RUnlock()
	user, ok := db.Users[UidToString(uid)]
	if !ok { //user does not exist
		return false, "", time.Now()
	}
	for _, uCookie := range user.Cookies {
		if uCookie.Cookie == cookie {
			if uCookie.Replace.Before(time.Now()) &&
				uCookie.Exp.After(time.Now()) {
				uCookie, err := newCookie()
				if err != nil {
					return false, "", time.Now()
				}
				return true, uCookie.Cookie, uCookie.Exp
			} else if uCookie.Exp.After(time.Now()) {
				return true, uCookie.Cookie, uCookie.Exp
			}
		}
	}
	return false, "", time.Now()
}

//Nickname validates the cookie and returns the user's nickname
func Nickname(uid []byte, cookie string) (string, error) {
	db.RLock()
	defer db.RUnlock()
	user, ok := db.Users[UidToString(uid)]
	if !ok {
		return "", new(UserDoesNotExist)
	}
	if ok, _, _ := Validate(cookie, uid); !ok {
		return "", new(AuthenticationError)
	}
	return user.Nick, nil
}

//UpdatePassword changes the password of a given user
func UpdatePassword(uid, pwd, nPwd []byte) error {
	db.RLock()
	user, ok := db.Users[UidToString(uid)]
	if !ok {
		db.RUnlock()
		return new(UserDoesNotExist)
	}
	if !Authenticate(uid, pwd) {
		db.RUnlock()
		return new(AuthenticationError)
	}
	db.RUnlock()
	db.Lock()
	defer db.Unlock()
	user.Pswrd = nPwd
	return nil
}

//UpdateNickname updates a users nickname having first established the existence
//of a user and validated the cookie
func UpdateNickname(uid []byte, cookie string, nickname string) error {
	db.RLock()
	user, ok := db.Users[UidToString(uid)]
	if !ok {
		db.RUnlock()
		return new(UserDoesNotExist)
	}
	if ok, _, _ := Validate(cookie, uid); !ok {
		db.RUnlock()
		return new(AuthenticationError)
	}
	db.RUnlock()
	db.Lock()
	defer db.Unlock()
	user.Nick = nickname
	return nil
}

// removes all feeds from user’s account.
func ResetUserFeeds(uid []byte) error {
	db.RLock()
	user, ok := db.Users[UidToString(uid)]
	db.RUnlock()
	if !ok {
		return new(UserDoesNotExist)
	}
	db.Lock()
	defer db.Unlock()
	user.Feeds = make([]*rss.Feed, 0)
	user.FeedUrls = make([]string, 0)
	return nil
}

// retrieves feed info. 
func Feeds(uid []byte) ([]*rss.Feed, error) {
	if !Exists(uid) {
		return nil, new(UserDoesNotExist)
	}
	db.RLock()
	defer db.RUnlock()
	user, _ := db.Users[UidToString(uid)]
	return user.Feeds, nil
}

// pushes update to user’s account.
// func Update(userID []byte, delta *Delta) error {
// 	return nil
// }
func AddFeeds(uid []byte, cookie string, urls ...string) error {
	if !Exists(uid) {
		return new(UserDoesNotExist)
	}
	db.Lock()
	defer db.Unlock()
	user, _ := db.Users[UidToString(uid)]
	for _, url := range urls {
		feed, err := rss.Fetch(url)
		if err != nil {
			return nil
		}
		user.Feeds = append(user.Feeds, feed)
		user.FeedUrls = append(user.FeedUrls, feed.Link)
	}
	return nil
}

func FeedsToJson(uid []byte, cookie string) ([]byte, error) {
	if ok, _, _ := Validate(cookie, uid); !ok {
		return nil, new(AuthenticationError)
	}
	feeds, err := Feeds(uid)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(feeds)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Debug() []byte {
	var buf bytes.Buffer
	buf.WriteString("\t === DATABASE DEBUG INFORMATION === \n")
	buf.WriteString(fmt.Sprintf("  Total Users: %d\n", len(db.Users)))
	buf.WriteString(fmt.Sprintf("  Total Salts: %d\n", len(db.Salts)))
	buf.WriteString(fmt.Sprintf("  Total Emails: %d\n", len(db.Emails)))
	return buf.Bytes()
}

func UidToString(uid []byte) string {
	return base64.URLEncoding.EncodeToString(uid)
}

func StringToUid(s string) ([]byte, error) {
	uidBytes := make([]byte, base64.URLEncoding.DecodedLen(len(s)))
	n, err := base64.URLEncoding.Decode(uidBytes, []byte(s))
	if err != nil {
		return nil, err
	}
	return uidBytes[:n], nil
}
