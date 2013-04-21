package server

import (
	"compress/gzip"
  "fmt"
	"html/template"
  "net/http"
  "rs3/database"
	"strings"
	"time"
)

func ServeMain(w http.ResponseWriter, r *http.Request) {
  uid, err := r.Cookie("uid")
  if err != nil {
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

	Template := new(MainTemplate)
  Template.Nickname, err = database.Nickname(uidBytes, auth.Value)
  if err != nil {
    fmt.Println("Failed to get nickname.")
    Template.Nickname = "[UNKNOWN]"
  }

	t, err := template.ParseFiles("server/content/html/main.html")
	if err != nil {
		fmt.Println("Failed to parse template.")
		fmt.Println(err)
		return
	}
	
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.Header().Add("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		err = t.ExecuteTemplate(w, "main.html", Template)
		if err != nil {
			fmt.Println("Failed to execute template.")
			fmt.Println(err)
			return
		}
	} else {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		err = t.ExecuteTemplate(gz, "main.html", Template)
		if err != nil {
			fmt.Println("Failed to execute template.")
			fmt.Println(err)
			return
		}
		gz.Close()
	}
}

type MainTemplate struct {
	Nickname string
}
