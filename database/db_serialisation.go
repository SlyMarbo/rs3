package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

var currentDatabase *bytes.Reader
var fullRead bool

func Reader() io.Reader {
	jsonData, err := toJson()
	if err != nil {
		return nil
	}
	
	return bytes.NewReader(jsonData)
}

type Database struct{}

func (d *Database) Write(json []byte) (int, error) {
	// backup
	err := fromJson(json)
	if err != nil {
		return 0, err
	}
	return len(json), nil
}

func toJson() ([]byte, error) {
	//db.RLock()
	//defer db.RUnlock()
	b, err := json.Marshal(db)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func fromJson(data []byte) error {
	err := json.Unmarshal(data, &db)
	if err != nil {
		fmt.Println("Failed to unmarshal JSON.")
		return err
	}
	for _, user := range db.Users {
		user.mutex = new(sync.RWMutex)
	}
	db.RWMutex = new(sync.RWMutex)
	return nil
}
