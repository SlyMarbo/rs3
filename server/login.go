package server

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"rs3/database"
	"rs3/security"
)

func serveLogin(w http.ResponseWriter, r *http.Request, failed bool) {
	var path string
	if failed {
		path = "server/content/html/failed_login.html"
	} else {
		path = "server/content/html/login.html"
	}
	data, err := ioutil.ReadFile(path)
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
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Error reading from login request:")
		log.Println(err)
		http.Error(w, "Could not read request body.", 400)
		return
	}
	
	if len(b) == 0 {
		serveLogin(w, r, false)
		return
	}
	
	body, err := url.QueryUnescape(string(b))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		http.Error(w, "Failed to process login.", 500)
		return
	}
	
	regex := regexp.MustCompile(`u=([\w\.\@]+)\&p=([\w]+)`)
	matches := regex.FindAllStringSubmatch(body, -1)
	if matches == nil {
		serveLogin(w, r, false)
		return
	}
	
	username := matches[0][1]
	password := matches[0][2]
	fmt.Printf("Found login attempt: %q, %q.\n", username, password)
	salt := database.Salt(username)
	if salt == nil {
		fmt.Printf("User %q does not exist.\n", username)
		w.WriteHeader(401)
		serveLogin(w, r, true)
		return
	}
	uid, err := security.Hash(username, salt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		http.Error(w, "Failed to process login.", 500)
		return
	}
	
	pwd, err := security.Hash(password, salt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		http.Error(w, "Failed to process login.", 500)
		return
	}
	
	cookie, expiry, err := database.Login(uid, pwd)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		http.Error(w, "Invalid login details.", 401)
		return
	}
	
	fmt.Println("Login successful")
	
	// Add the uid and auth cookies.
	w.Header().Add("Set-Cookie", fmt.Sprintf("uid=%s; Expires=%s; Secure; HttpOnly", string(uid),
		expiry.UTC().Format(http.TimeFormat)))
	w.Header().Add("Set-Cookie", fmt.Sprintf("auth=%s; Expires=%s; Secure; HttpOnly", cookie,
		expiry.UTC().Format(http.TimeFormat)))
	
	r.Header.Add("Set-Cookie", fmt.Sprintf("uid=%s; Expires=%s; Secure; HttpOnly", string(uid),
		expiry.UTC().Format(http.TimeFormat)))
	r.Header.Add("Set-Cookie", fmt.Sprintf("auth=%s; Expires=%s; Secure; HttpOnly", cookie,
		expiry.UTC().Format(http.TimeFormat)))
	
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		ServeMain(w, r)
		return
	}
	
	url := r.URL
	url.Path = "/"
	http.Redirect(w, r, url.String(), 307)
	return
}
