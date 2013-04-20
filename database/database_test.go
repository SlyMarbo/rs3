package database

import (
	"bytes"
	"testing"
)

var buf *bytes.Buffer
var test *Database
var cookie string
var userID = []byte("user ID")
var passwordHash = []byte("password hash")
var nickname = "nickname"
var gibberish = []byte("gibberish")

func init() {
	buf = bytes.NewBuffer(nil)
}

func TestDatabaseLogic(t *testing.T) {
	
	// Check empty databases are empty.
	test = NewDatabase()
	n, err := io.Copy(buf, test)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if n != 0 {
		t.Error("Empty database wrote data:")
		t.Error(buf.String())
		t.Fail()
		buf.Reset()
	}
	if len(test.Debug()) != 0 {
		t.Error("Empty database gave debug data.")
		t.Fail()
	}
	
	// Try adding a user.
	err = test.AddUser(userID, passwordHash, [32]byte{}, nickname)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	err = test.AddUser(userID, gibberish, [32]byte{}, gibberish)
	if _, ok := err.(UserAlreadyExists); !ok {
		t.Error("Failed to detect creation of duplicate user.")
		t.Fail()
	}
	
	// Check exists.
	if !test.Exists(userID) {
		t.Error("Failed to detect user.")
		t.Fail()
	}
	if test.Exists(gibberish) {
		t.Error("Detected non-existant user.")
		t.Fail()
	}
	
	// Check authentication.
	if !test.Authenticate(userID, passwordHash) {
		t.Error("Failed to authenticate valid user.")
		t.Fail()
	}
	if test.Authenticate(userID, gibberish) {
		t.Error("Authenticated valid user with invalid password.")
		t.Fail()
	}
	if test.Authenticate(gibberish, passwordHash) {
		t.Error("Authenticated invalid user with valid password.")
		t.Fail()
	}
	
	// Check login.
	_, err := test.Login(gibberish, passwordHash)
	if _, ok := err.(UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user login attempt.")
		t.Fail()
	}
	_, err := test.Login(userID, gibberish)
	if _, ok := err.(AuthenticationFailure); !ok {
		t.Error("Failed to detect invalid password hash login attempt.")
		t.Fail()
	}
	cookie, err := test.Login(userID, passwordHash)
	if err != nil {
		t.Error("Failed to login valid user.")
		t.Fail()
	}
	if len(cookie) < 25 {
		t.Error("Cookie is too short: ", len(cookie))
		t.Fail()
	}
	
	// Check validation.
	if !test.Validate(cookie, userID) {
		t.Error("Failed to validate correct details.")
		t.Fail()
	}
	if test.Validate(cookie, gibberish) {
		t.Error("Validated good cookie for the wrong user.")
		t.Fail()
	}
	if test.Validate("gibberish", userID) {
		t.Error("Validated bad cookie with valid user.")
		t.Fail()
	}
	
	// Check updating password.
	err = test.UpdatePassword(userID, gibberish, []byte("more stuff"))
	if _, ok := err.(AuthenticationFailure); !ok {
		t.Error("Allowed an unauthenticated change of password.")
		t.Fail()
	}
	err = test.UpdatePassword(gibberish, gibberish, []byte("more stuff"))
	if _, ok := err.(UserDoesNotExist); !ok {
		t.Error("Failed to detect a non-existant user in password update.")
		t.Fail()
	}
	err = test.UpdatePassword(userID, passwordHash, []byte("passwordHash"))
	if err != nil {
		t.Error("Failed to change password of authentic user.")
		t.Fail()
	}
	if !test.Authenticate(userID, []byte("passwordHash")) {
		t.Error("Failed to authenticate user after password change.")
		t.Fail()
	}
	
	// Check updating nickname.
	nick, err := test.Nickname(userID, cookie)
	if err != nil {
		t.Error("Failed to provide nickname for valid user.")
		t.Fail()
	}
	if nick != "nickname" {
		t.Error("Failed to provide correct nickname for valid user: ", nick)
		t.Fail()
	}
	_, err = test.Nickname(userID, "gibberish")
	if _, ok := err.(AuthenticationFailure); !ok {
		t.Error("Failed to detect invalid cookie on nickname request.")
		t.Fail()
	}
	_, err = test.Nickname(gibberish, "gibberish")
	if _, ok := err.(UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user in nickname request.")
		t.Fail()
	}
	err = test.UpdateNickname(userID, "gibberish", "gibberish")
	if _, ok := err.(AuthenticationFailure); !ok {
		t.Error("Allowed an unauthenticated change of nickname.")
		t.Fail()
	}
	err = test.UpdateNickname(gibberish, "gibberish", "gibberish")
	if _, ok := err.(UserDoesNotExist); !ok {
		t.Error("Failed to detect a non-existant user in nickname update.")
		t.Fail()
	}
	err = test.UpdateNickname(userID, cookie, "nickName")
	if err != nil {
		t.Error("Failed to change nickname of authentic user.")
		t.Fail()
	}
	nick, err := test.Nickname(userID, cookie)
	if err != nil {
		t.Error("Failed to provide nickname for valid user.")
		t.Fail()
	}
	if nick != "nickName" {
		t.Error("Failed to provide correct nickname for valid user after change: ", nick)
		t.Fail()
	}
	
	// Check feeds.
	feeds, err := test.Feeds(userID)
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
	_, err = test.Feeds(gibberish)
	if _, ok := err.(UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user in feeds request.")
		t.Fail()
	}
	
	// TODO: Add feeds
	
	// Check feed reset.
	err = test.ResetUserFeeds(userID)
	if err != nil {
		t.Error("Failed to reset feeds for valid user.")
		t.Fail()
	}
	feeds, err := test.Feeds(userID)
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
	err = test.ResetUserFeeds(gibberish)
	if _, ok := err.(UserDoesNotExist); !ok {
		t.Error("Failed to detect non-existant user in feed reset request.")
		t.Fail()
	}
	
	// Check deletion.
	err = test.DeleteUser(gibberish)
	if _, ok := err.(UserDoesNotExist); !ok {
		t.Error("Failed to detect deletion of non-existant user.")
		t.Fail()
	}
	err = test.DeleteUser(userID)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	
	// TODO: check backup and restore.
}
