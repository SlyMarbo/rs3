package database

import (
	"errors"
)

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

func (b BackupFailure) Append(err error) error {
	return errors.New(b.Error() + ":" + err.Error())
}

func (err BackupFailure) Error() string {
	return "Failed to Backup Database"
}

type RestoreFailure struct{}

func (r RestoreFailure) Append(err error) error {
	return errors.New(r.Error() + ":" + err.Error())
}

func (err RestoreFailure) Error() string {
	return "Failed to Restore Database"
}
