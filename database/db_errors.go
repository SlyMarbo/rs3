package database

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
