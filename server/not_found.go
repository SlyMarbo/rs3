package server

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func NotFound(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Could not find %q.\n", r.RequestURI)
	data, err := ioutil.ReadFile("server/content/html/404.html")
	if err != nil {
		log.Println("Failed to open 404.html:")
		log.Println(err)
		return
	}
	
	_, err = w.Write(data)
	if err != nil {
		log.Println("Failed to send 404.html:")
		log.Println(err)
		return
	}
}
