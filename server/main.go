package server

import (
	"fmt"
	"net/http"
	"rs3/database"
)

func ServeMain(w http.ResponseWriter, r *http.Request) {
	uid, err := r.Cookie("uid")
	if err != nil {
		Login(w, r)
		return
	}
	auth, err := r.Cookie("auth")
	if err != nil {
		Login(w, r)
		return
	}
	
	if !uid.Secure || !uid.HttpOnly || !auth.Secure || !auth.HttpOnly {
		fmt.Println("A cookie is not secure and/or HTTP only.")
		fmt.Println(uid)
		fmt.Println(auth)
		http.Error(w, "Invalid cookies", 401)
		return
	}
	
	valid, cookie, expiry := database.Validate(auth, []byte(uid))
	if !valid {
		Login(w, r)
		return
	}
	
	if cookie != auth {
		w.Header().Add("Set-Cookie", fmt.Sprintf("auth=%s; Expires=%s; Secure; HttpOnly", cookie,
			expiry.UTC().Format(http.TimeFormat)))
		r.Header.Add("Set-Cookie", fmt.Sprintf("auth=%s; Expires=%s; Secure; HttpOnly", cookie,
			expiry.UTC().Format(http.TimeFormat)))
	}
	
	data, err := ioutil.ReadFile("server/content/html/main.html")
	if err != nil {
		log.Println("Failed to open main.html:")
		log.Println(err)
		return
	}
	
	_, err = w.Write(data)
	if err != nil {
		log.Println("Failed to send main.html:")
		log.Println(err)
		return
	}
}
