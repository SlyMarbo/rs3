package database

import (
	"bytes"
	"fmt"
	"github.com/SlyMarbo/rss"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	sec "rs3/security"
	"sync"
	"time"
)

var db *database

func init() {
	rand.Seed(time.Now().UnixNano())
	db = newDatabase()
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
	exp     time.Time
	replace time.Time
	cookie  string
}

type CookieJar []Cookie

func newCookie() Cookie {
	var buf bytes.Buffer
	for i := 0; i < 5; i++ {
		buf.WriteString(fmt.Sprintf("%x", rand.Int63()))
	}
	cookie := Cookie{
		time.Now().Add(7 * 24 * time.Hour),
		time.Now().Add(14 * 24 * time.Hour),
		buf.String()[:256]}
	return cookie
}

type UserAlreadyExists struct{}

func (err UserAlreadyExists) Error() string {
	return "User ID Already Exists"
}

type UserDoesNotExist struct{}

func (err UserDoesNotExist) Error() string {
	return "User ID Does Not Exist"
}

type EmailAlreadyExists struct{}

func (err EmailAlreadyExists) Error() string {
	return "Email Already Exists"
}

type AuthenticationError struct{}

func (err AuthenticationError) Error() string {
	return "Authentication Failure, User ID or Password Incorrect"
}

type BackupFailure struct{}

func (err BackupFailure) Error() string {
	return "Failed to Backup Database"
}

type RestoreFailure struct{}

func (err RestoreFailure) Error() string {
	return "Failed to Restore Database"
}

type database struct {
	users  map[string]*User     //uid -> User
	salts  map[string]*sec.Salt //email -> Salt
	emails map[string]struct{}  //email -> null (for email existence check)
	mutex  *sync.RWMutex
}

type Database struct{}

// func NewDatabase() *Database
func newDatabase() *database {
	db := database{
		make(map[string]*User),
		make(map[string]*sec.Salt),
		make(map[string]struct{}),
		new(sync.RWMutex),
	}
	return &db
}

func Salt(email string) *sec.Salt {
	return db.salts[email]
}

//AddUser creates a new user and adds it to the database. It establishes that both the user
//does not exist and that their email is not in use
func AddUser(uid, pwd []byte, salt *sec.Salt, nick, email string) error {
	db.mutex.RLock()
	if _, ok := db.users[string(uid)]; ok {
		db.mutex.RUnlock()
		return new(UserAlreadyExists)
	}
	if _, ok := db.emails[string(uid)]; ok {
		db.mutex.RUnlock()
		return new(EmailAlreadyExists)
	}
	db.mutex.RUnlock()
	db.mutex.Lock()
	defer db.mutex.Unlock()
	user := newUser(uid, pwd, salt, nick)
	db.users[string(uid)] = user
	db.emails[email] = *new(struct{})
	return nil
}

//Delete user removes a user from the database provided they exist in the system
func DeleteUser(uid []byte) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	if _, ok := db.users[string(uid)]; !ok {
		return new(UserDoesNotExist)
	}
	delete(db.users, string(uid))
	return nil
}

//Exists confirms whether or not a user exists in the system
func Exists(uid []byte) bool {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	_, ok := db.users[string(uid)]
	return ok
}

//Authenticate checks that the userID and password match.
func Authenticate(uid, pswd []byte) bool {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	user, ok := db.users[string(uid)]
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
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	if !Authenticate(uid, pswd) {
		return "", time.Now(), new(AuthenticationError)
	}
	user, ok := db.users[string(uid)]
	if !ok {
		return "", time.Now(), new(UserDoesNotExist)
	}
	if len(user.Cookies) != 0 {
		for i := 0; i < len(user.Cookies); i++ {
			if user.Cookies[i].exp.After(time.Now()) {
				return user.Cookies[i].cookie, user.Cookies[i].exp, nil
			}
		}
		c := newCookie()
		user.Cookies = append(user.Cookies, c)
		return c.cookie, c.exp, nil
	} else {
		user.Cookies = append(user.Cookies, newCookie())
		return user.Cookies[0].cookie, user.Cookies[0].exp, nil
	}
}

//Validate checks the cookie.
func Validate(cookie string, uid []byte) bool {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	user, ok := db.users[string(uid)]
	if !ok { //user does not exist
		return false
	}
	for _, uCookie := range user.Cookies {
		if uCookie.cookie == cookie {
			return true
		}
	}
	return false
}

//Nickname validates the cookie and returns the user's nickname
func Nickname(uid []byte, cookie string) (string, error) {
	if !Validate(cookie, uid) {
		return "", new(AuthenticationError)
	}
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	user, ok := db.users[string(uid)]
	if !ok {
		return "", new(UserDoesNotExist)
	}
	return user.Nick, nil
}

//UpdatePassword changes the password of a given user
func UpdatePassword(uid, pwd, nPwd []byte) error {
	db.mutex.RLock()
	user, ok := db.users[string(uid)]
	if !ok {
		db.mutex.RUnlock()
		return new(UserDoesNotExist)
	}
	if !Authenticate(uid, pwd) {
		db.mutex.RUnlock()
		return new(AuthenticationError)
	}
	db.mutex.RUnlock()
	db.mutex.Lock()
	defer db.mutex.Unlock()
	user.Pswrd = nPwd
	return nil
}

//UpdateNickname updates a users nickname having first established the existence
//of a user and validated the cookie
func UpdateNickname(uid []byte, cookie string, nickname string) error {
	db.mutex.RLock()
	user, ok := db.users[string(uid)]
	if !ok {
		db.mutex.RUnlock()
		return new(UserDoesNotExist)
	}
	if !Validate(cookie, uid) {
		db.mutex.RUnlock()
		return new(AuthenticationError)
	}
	db.mutex.RUnlock()
	db.mutex.Lock()
	defer db.mutex.Unlock()
	user.Nick = nickname
	return nil
}

// removes all feeds from user’s account.
func ResetUserFeeds(uid []byte) error {
	db.mutex.RLock()
	user, ok := db.users[string(uid)]
	db.mutex.Unlock()
	if !ok {
		return new(UserDoesNotExist)
	}
	db.mutex.Lock()
	defer db.mutex.Unlock()
	user.Feeds = make([]*rss.Feed, 0)
	user.FeedUrls = make([]string, 0)
	return nil
}

// retrieves feed info. 
func Feeds(uid []byte) ([]*rss.Feed, error) {
	if !Exists(uid) {
		return nil, new(UserDoesNotExist)
	}
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	user, _ := db.users[string(uid)]
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
	db.mutex.Lock()
	defer db.mutex.Unlock()
	user, _ := db.users[string(uid)]
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		feed, err := rss.Parse(body)
		if err != nil {
			return nil
		}
		user.Feeds = append(user.Feeds, feed)
		user.FeedUrls = append(user.FeedUrls, feed.Link)
	}
	return nil
}

func Debug() []byte {
	return nil
}

func (d *Database) Write([]byte) (int, error) {
	// restore
	return 0, nil
}

func (d *Database) Read([]byte) (int, error) {
	// backup
	return 0, nil
}

func Backup(path string) error {
	_, err := os.Create(path)
	if err != nil {
		return err
	}
	return nil
}

func Restore(path string) error {
	return nil
}
