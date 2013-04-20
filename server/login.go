package server

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"rs3/database"
	"rs3/security"
)

func ServeLogin(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadFile("content/html/login.html")
	if err != nil {
		log.Println("Failed to open login.html:")
		log.Println(err)
		return
	}
	
	_, err = w.Write(data)
	if err != nil {
		log.Println("Failed to send login.html:")
		log.Println(err)
		return
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Error reading from login request:")
		log.Println(err)
		http.Error(w, "Could not read request body.", 400)
		return
	}
	
	regex := regexp.MustCompile(`u=([\w\.\@]+)&p=([\w\.\@]+)`)
	matches := regex.FindAllStringSubmatch(string(body))
	if matches == nil {
		return ServeLogin(w, r)
	}
	
	username = matches[0][1]
	password = matches[0][2]
	fmt.Printf("Found login attempt: %q, %q.\n", username, password)
	salt := database.Salt(username)
	uid, err := database.Hash(username, salt)
	if err != nil {
		fmt.Fprintf(os.Stderr, err)
		http.Error(w, "Failed to process login.", 500)
		return
	}
	
	pwd, err := database.Hash(password, salt)
	if err != nil {
		fmt.Fprintf(os.Stderr, err)
		http.Error(w, "Failed to process login.", 500)
		return
	}
	
	cookie, expiry, err := database.Login(uid, pwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, err)
		http.Error(w, "Invalid login details.", 401)
		return
	}
	
	fmt.Println("Login successful")
	
	// Add the uid and auth cookies.
	w.Header().Add("Set-Cookie", fmt.Sprintf("uid=%s; Expires=%s; Secure; HttpOnly", string(uid),
		expiry.UTC().Format(http.TimeFormat)))
	w.Header().Add("Set-Cookie", fmt.Sprintf("auth=%s; Expires=%s; Secure; HttpOnly", cookie,
		expiry.UTC().Format(http.TimeFormat)))
	
	r.Header().Add("Set-Cookie", fmt.Sprintf("uid=%s; Expires=%s; Secure; HttpOnly", string(uid),
		expiry.UTC().Format(http.TimeFormat)))
	r.Header().Add("Set-Cookie", fmt.Sprintf("auth=%s; Expires=%s; Secure; HttpOnly", cookie,
		expiry.UTC().Format(http.TimeFormat)))
	
	if r.URL.path == "/" || r.URL.path == "/index.html" {
		return ServeMain(w, r)
	}
	
	url := r.URL
	url.Path = "/"
	return http.Redirect(w, r, url.String(), 307)
}
