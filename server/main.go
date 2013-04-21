package server

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"rs3/database"
)

func ServeMain(w http.ResponseWriter, r *http.Request) {
	uid, err := r.Cookie("uid")
	if err != nil {
		fmt.Println("no uid cookie")
		Login(w, r)
		return
	}
	uidBytes, err := database.StringToUid(uid.Value)
	if err != nil {
		fmt.Println("failed to parse cookie")
		Login(w, r)
		return
	}
	auth, err := r.Cookie("auth")
	if err != nil {
		fmt.Println("no auth cookie")
		Login(w, r)
		return
	}
	
	valid, cookie, expiry := database.Validate(auth.Value, uidBytes)
	if !valid {
		fmt.Println("cookie not valid")
		Login(w, r)
		return
	}
	
	if cookie != auth.Value {
		w.Header().Add("Set-Cookie", fmt.Sprintf("auth=%q; Expires=%s; Secure; HttpOnly", cookie,
			expiry.UTC().Format(http.TimeFormat)))
		r.Header.Add("Set-Cookie", fmt.Sprintf("auth=%q; Expires=%s; Secure; HttpOnly", cookie,
			expiry.UTC().Format(http.TimeFormat)))
	}
	
	data, err := ioutil.ReadFile("server/content/html/main.html")
	if err != nil {
		fmt.Println("Failed to open main.html:")
		fmt.Println(err)
		return
	}
	
	_, err = w.Write(data)
	if err != nil {
		fmt.Println("Failed to send main.html:")
		fmt.Println(err)
		return
	}
}
