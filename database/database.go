package database

import (
	"bytes"
	"compress/gzip"
	//	"crypto/aes"
	//	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/SlyMarbo/rss"
	"io"
	"io/ioutil"
	"net/http"
	"os"
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

type Database struct{}

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
	exp     time.Time
	replace time.Time
	cookie  string
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
	if _, ok := db.Users[string(uid)]; ok {
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
	db.Users[string(uid)] = user
	db.Salts[email] = salt
	db.Emails[email] = *new(struct{})
	return nil
}

//Delete user removes a user from the database provided they exist in the system
func DeleteUser(uid []byte) error {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.Users[string(uid)]; !ok {
		return new(UserDoesNotExist)
	}
	delete(db.Users, string(uid))
	return nil
}

//Exists confirms whether or not a user exists in the system
func Exists(uid []byte) bool {
	db.RLock()
	defer db.RUnlock()
	_, ok := db.Users[string(uid)]
	return ok
}

//Authenticate checks that the userID and password match.
func Authenticate(uid, pswd []byte) bool {
	db.RLock()
	defer db.RUnlock()
	user, ok := db.Users[string(uid)]
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
	user, ok := db.Users[string(uid)]
	if !ok {
		return "", time.Now(), new(UserDoesNotExist)
	}
	if !Authenticate(uid, pswd) {
		return "", time.Now(), new(AuthenticationError)
	}
	if len(user.Cookies) != 0 {
		for i := 0; i < len(user.Cookies); i++ {
			if user.Cookies[i].exp.After(time.Now()) {
				return user.Cookies[i].cookie, user.Cookies[i].exp, nil
			}
		}
		c, err := newCookie()
		if err != nil {
			return "", time.Now(), err
		}
		user.Cookies = append(user.Cookies, c)
		return c.cookie, c.exp, nil
	} else {
		c, err := newCookie()
		if err != nil {
			return "", time.Now(), err
		}
		user.Cookies = append(user.Cookies, c)
		return user.Cookies[0].cookie, user.Cookies[0].exp, nil
	}
}

//Validate checks the cookie.
func Validate(cookie string, uid []byte) bool {
	db.RLock()
	defer db.RUnlock()
	user, ok := db.Users[string(uid)]
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
	db.RLock()
	defer db.RUnlock()
	user, ok := db.Users[string(uid)]
	if !ok {
		return "", new(UserDoesNotExist)
	}
	if !Validate(cookie, uid) {
		return "", new(AuthenticationError)
	}
	return user.Nick, nil
}

//UpdatePassword changes the password of a given user
func UpdatePassword(uid, pwd, nPwd []byte) error {
	db.RLock()
	user, ok := db.Users[string(uid)]
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
	user, ok := db.Users[string(uid)]
	if !ok {
		db.RUnlock()
		return new(UserDoesNotExist)
	}
	if !Validate(cookie, uid) {
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
	user, ok := db.Users[string(uid)]
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
	user, _ := db.Users[string(uid)]
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
	user, _ := db.Users[string(uid)]
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
	var buf bytes.Buffer
	buf.WriteString("\t === DATABASE DEBUG INFORMATION === \n")
	buf.WriteString(fmt.Sprintf("  Total Users: %d\n", len(db.Users)))
	buf.WriteString(fmt.Sprintf("  Total Salts: %d\n", len(db.Salts)))
	buf.WriteString(fmt.Sprintf("  Total Emails: %d\n", len(db.Emails)))
	return buf.Bytes()
}

func (d *Database) Write(json []byte) (int, error) {
	// backup
	err := fromJson(json)
	if err != nil {
		return 0, err
	}
	return len(json), nil
}

func (d *Database) Read(b []byte) (int, error) {
	// restore
	dBytes, err := toJson()
	if err != nil {
		return 0, err
	}
	i := 0
	for l, m := len(b), len(dBytes); i < l && i < m; i++ {
		b[i] = dBytes[i]
	}
	return i, io.EOF
}

func Backup(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	zipper := gzip.NewWriter(buf)
	_, err = io.Copy(zipper, new(Database))
	if err != nil {
		return err
	}
	zipper.Close()
	_, err = io.Copy(f, buf)
	//	fmt.Println(buf.Bytes())
	// var key, iv []byte
	// _, err = os.Open("database/backup.key")
	// if os.IsNotExist(err) {
	// 	key = make([]byte, 32) //256 bits
	// 	_, err := io.ReadFull(rand.Reader, key)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	iv = make([]byte, aes.BlockSize)
	// 	_, err = io.ReadFull(rand.Reader, iv)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	newKeyFile, err := os.Create("database/backup.key")
	// 	if err != nil {
	// 		return err
	// 	}
	// 	newKeyFile.Write(key)
	// 	ivFile, err := os.Create("database/iv.key")
	// 	if err != nil {
	// 		return err
	// 	}
	// 	ivFile.Write(iv)
	// } else {
	// 	key = make([]byte, 32)
	// 	key, err := ioutil.ReadFile("database/backup.key")
	// 	fmt.Println(key, len(key))
	// 	if err != nil {
	// 		return err
	// 	}
	// 	iv = make([]byte, aes.BlockSize)
	// 	iv, err = ioutil.ReadFile("database/iv.key")
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	// block, err := aes.NewCipher(key)
	// if err != nil {
	// 	return err
	// }
	// encrypter := cipher.NewCBCEncrypter(block, iv)
	// if err != nil {
	// 	return err
	// }
	// if dif := buf.Len() % aes.BlockSize; dif != 0 {
	// 	dif = aes.BlockSize - dif
	// 	for i := 0; i < dif; i++ {
	// 		buf.Write([]byte{byte(dif)})
	// 	}
	// } else {
	// 	for i := 0; i < aes.BlockSize; i++ {
	// 		buf.Write([]byte{byte(aes.BlockSize)})
	// 	}
	// }
	// data := make([]byte, buf.Len())
	// fmt.Println("Backed Up Data", buf.Bytes())
	// encrypter.CryptBlocks(data, buf.Bytes())
	//	_, err = io.Copy(buf, new(Database))
	//_, err = f.Write(buf.Bytes())
	return err
}

func Restore(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	unzipper, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	unzipper.Close()
	_, err = io.Copy(new(Database), unzipper)
	// var key, iv []byte
	// _, err := os.Open("database/backup.key")
	// if os.IsNotExist(err) {
	// 	return err
	// } else {
	// 	key, err = ioutil.ReadFile("database/backup.key")
	// 	fmt.Println(key)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	iv, err = ioutil.ReadFile("database/iv.key")
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	// block, err := aes.NewCipher(key)
	// if err != nil {
	// 	return err
	// }
	// decrypter := cipher.NewCBCDecrypter(block, iv)
	// data, err := ioutil.ReadFile(path)
	// fmt.Println(data)
	// if err != nil {
	// 	return err
	// }

	//	buf := make([]byte, len(data))
	//	decrypter.CryptBlocks(buf, data)
	//	fmt.Println("Restored Data", buf)

	//	dif := int(buf[len(buf)-1]) + 1
	//	buf = buf[:len(buf)-dif]

	//	r := bytes.NewReader(buf)
	//	fmt.Println(len(data))
	//	_, err = io.Copy(new(Database), buf)
	return err
}

func toJson() ([]byte, error) {
	//db.RLock()
	//defer db.RUnlock()
	b, err := json.Marshal(db)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func fromJson(data []byte) error {
	err := json.Unmarshal(data, &db)
	if err != nil {
		return err
	}
	db.RWMutex = new(sync.RWMutex)
	return nil
}

/*
 DATABASE ERRORS
*/
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
