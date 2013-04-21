package server

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func NotFound(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Could not find %q.\n", r.RequestURI)
	data, err := ioutil.ReadFile("server/content/html/404.html")
	if err != nil {
		fmt.Println("Failed to open 404.html:")
		fmt.Println(err)
		return
	}
	
	_, err = w.Write(data)
	if err != nil {
		fmt.Println("Failed to send 404.html:")
		fmt.Println(err)
		return
	}
}
