package server

import (
	"io/ioutil"
	"log"
	"net/http"
)

func NotFound(w http.ResponseWriter, r *http.Request) {
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
