package database

import (
	"bytes"
	"fmt"
	"rs3/security"
	"testing"
)

var buf *bytes.Buffer
var test = &Database{}
var cookie string
var userID = []byte("user ID")
var passwordHash = []byte("password hash")
var nickname = "nickname"
var email = "marbo_is_a_fool@gmail.com"
var gibberish = []byte("gibberish")

func init() {
	buf = bytes.NewBuffer(nil)
}

func TestDatabaseLogic(t *testing.T) {

	// // Check empty databases are empty.
	// n, err := io.Copy(buf, test)
	// if err != nil {
	// 	t.Error(err)
	// 	t.Fail()
	// }
	// if n != 0 {
	// 	t.Error("Empty database wrote data:")
	// 	t.Error(buf.String())
	// 	t.Fail()
	// 	buf.Reset()
	// }

	// Try adding a user.
	err := AddUser(userID, passwordHash, security.NewSalt(), nickname, email)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	err = AddUser(userID, gibberish, security.NewSalt(), string(gibberish), email)
	if _, ok := err.(*UserAlreadyExists); !ok {
		t.Error("Failed to detect creation of duplicate user.")
		t.Fail()
	}

	// Check exists.
	if !Exists(userID) {
		t.Error("Failed to detect user.")
		t.Fail()
	}
	if Exists(gibberish) {
		t.Error("Detected non-existant user.")
		t.Fail()
	}

	// Check authentication.
	if !Authenticate(userID, passwordHash) {
		t.Error("Failed to authenticate valid user.")
		t.Fail()
	}
	if Authenticate(userID, gibberish) {
		t.Error("Authenticated valid user with invalid password.")
		t.Fail()
	}
	if Authenticate(gibberish, passwordHash) {
		t.Error("Authenticated invalid user with valid password.")
		t.Fail()
	}

	// Check login.
	_, _, err = Login(gibberish, passwordHash)
	if _, ok := err.(*UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user login attempt.")
		t.Fail()
	}
	_, _, err = Login(userID, gibberish)
	if _, ok := err.(*AuthenticationError); !ok {
		t.Error("Failed to detect invalid password hash login attempt.")
		t.Fail()
	}
	cookie, _, err := Login(userID, passwordHash)
	if err != nil {
		t.Error("Failed to login valid user.")
		t.Fail()
	}
	if len(cookie) < 25 {
		t.Error("Cookie is too short: ", len(cookie))
		t.Fail()
	}

	// Check validation.
	if !Validate(cookie, userID) {
		t.Error("Failed to validate correct details.")
		t.Fail()
	}
	if Validate(cookie, gibberish) {
		t.Error("Validated good cookie for the wrong user.")
		t.Fail()
	}
	if Validate("gibberish", userID) {
		t.Error("Validated bad cookie with valid user.")
		t.Fail()
	}

	// Check updating password.
	err = UpdatePassword(userID, gibberish, []byte("more stuff"))
	if _, ok := err.(*AuthenticationError); !ok {
		t.Error("Allowed an unauthenticated change of password.")
		t.Fail()
	}
	err = UpdatePassword(gibberish, gibberish, []byte("more stuff"))
	if _, ok := err.(*UserDoesNotExist); !ok {
		t.Error("Failed to detect a non-existant user in password update.")
		t.Fail()
	}
	err = UpdatePassword(userID, passwordHash, []byte("passwordHash"))
	if err != nil {
		t.Error("Failed to change password of authentic user.")
		t.Fail()
	}
	if !Authenticate(userID, []byte("passwordHash")) {
		t.Error("Failed to authenticate user after password change.")
		t.Fail()
	}

	// Check updating nickname.
	nick, err := Nickname(userID, cookie)
	if err != nil {
		t.Error("Failed to provide nickname for valid user.")
		t.Fail()
	}
	if nick != "nickname" {
		t.Error("Failed to provide correct nickname for valid user: ", nick)
		t.Fail()
	}
	_, err = Nickname(userID, "gibberish")
	if _, ok := err.(*AuthenticationError); !ok {
		t.Error("Failed to detect invalid cookie on nickname request.")
		t.Fail()
	}
	_, err = Nickname(gibberish, "gibberish")
	if _, ok := err.(*UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user in nickname request.")
		t.Fail()
	}
	err = UpdateNickname(userID, "gibberish", "gibberish")
	if _, ok := err.(*AuthenticationError); !ok {
		t.Error("Allowed an unauthenticated change of nickname.")
		t.Fail()
	}
	err = UpdateNickname(gibberish, "gibberish", "gibberish")
	if _, ok := err.(*UserDoesNotExist); !ok {
		t.Error("Failed to detect a non-existant user in nickname update.")
		t.Fail()
	}
	err = UpdateNickname(userID, cookie, "nickName")
	if err != nil {
		t.Error("Failed to change nickname of authentic user.")
		t.Fail()
	}
	nick, err = Nickname(userID, cookie)
	if err != nil {
		t.Error("Failed to provide nickname for valid user.")
		t.Fail()
	}
	if nick != "nickName" {
		t.Error("Failed to provide correct nickname for valid user after change: ", nick)
		t.Fail()
	}

	// Check feeds.
	feeds, err := Feeds(userID)
	if err != nil {
		t.Error("Failed to provide feeds for valid user.")
		t.Fail()
	}
	if feeds == nil {
		t.Error("Provided nil feeds for valid user.")
		t.Fail()
	}
	if len(feeds) != 0 {
		t.Error("Feeds given for empty user.")
		t.Fail()
	}
	_, err = Feeds(gibberish)
	if _, ok := err.(*UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user in feeds request.")
		t.Fail()
	}

	// TODO: Add feeds

	// Check feed reset.
	err = ResetUserFeeds(userID)
	if err != nil {
		t.Error("Failed to reset feeds for valid user.")
		t.Fail()
	}

	feeds, err = Feeds(userID)
	if err != nil {
		t.Error("Failed to provide feeds for valid user after reset.")
		t.Fail()
	}
	if feeds == nil {
		t.Error("Provided nil feeds for valid user after reset.")
		t.Fail()
	}

	if len(feeds) != 0 {
		t.Error("Feeds given for user after reset.")
		t.Fail()
	}
	err = ResetUserFeeds(gibberish)
	if _, ok := err.(*UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user in feed reset request.")
		t.Fail()
	}

	// Check deletion.
	err = DeleteUser(gibberish)
	if _, ok := err.(*UserDoesNotExist); !ok {
		t.Error("Failed to detect deletion of non-existant user.")
		t.Fail()
	}
	err = DeleteUser(userID)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	fmt.Println("END")
	// TODO: check backup and restore.
}

func TestDatabaseBackupAndRestore(t *testing.T) {
	AddUser([]byte("THIS IS A UID"),
		[]byte("THIS IS A PASSWORD"),
		security.NewSalt(),
		"THIS IS A NICKNAME",
		"marbo_is_a_bellend@example.com")
	b, _ := toJson()
	fmt.Println(string(b))

	_ = fromJson(b)
	fmt.Println(string(Debug()))
	user := db.Users["THIS IS A UID"]
	fmt.Println(string(user.Uid))
	fmt.Println(string(user.Pswrd))

	err := Backup("test_backup.enc")
	if err != nil {
		fmt.Println(err)
	}
	err = Restore("test_backup.enc")
	if err != nil {
		return err
	}
	if user, ok := db.Users["THIS IS A UID"]; ok {
		fmt.Println(string(user.Uid))
		fmt.Println(string(user.Pswrd))
	} else {
		fmt.Println("FUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU")
	}
}
