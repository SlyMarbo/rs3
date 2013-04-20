package database

import (
	"bufio"
	"fmt"
  "log"
  "os"
	"rs3/security"
	"runtime/pprof"
	"strings"
)

func Console() {
  scanner := bufio.NewScanner(os.Stdin)
  for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), " ")
		switch {
			
		// Add user.
		case tokens[0] == "add":
			username := tokens[1]
			password := tokens[2]
			nickname := tokens[3]
			salt := security.NewSalt()
			
			uid, err := security.Hash(username, salt)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error: failed to hash username.")
			}
			
			pwd, err := security.Hash(password, salt)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error: failed to hash username.")
			}
			
			err = db.AddUser(uid, pwd, salt, nickname, username)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			}
			
		// Remove user.
		case tokens[0] == "remove":
			username := tokens[1]
			salt := db.Salt(username)
			
			uid, err := security.Hash(username, salt)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error: failed to hash username.")
			}
			
			err = db.DeleteUser()
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			}
			
		// Debug.
		case tokens[0] == "debug":
			fmt.Println(db.Debug())
			
		// Stack trace.
		case tokens[0] == "stacktrace":
			target := tokens[1]
			f, err := os.Create(target)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error: failed to open target filepath.")
			}
			w := bufio.NewWriter(f)
			err = pprof.Lookup("goroutine").WriteTo(w, 0)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error: failed to write stacktrace.")
			}
			
		// Backup database.
		case tokens[0] == "backup":
			target := tokens[1]
			db.Backup(target)
			
		// Restore database.
		case tokens[0] == "restore":
			origin := tokens[1]
			db.Restore(origin)
			
		// Cache content file.
		case tokens[0] == "cache":
			target := tokens[1]
			err := Cache(target)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			}
			
		}
  }
  if err := scanner.Err(); err != nil {
    log.Fatal(os.Stderr, "reading standard input:", err)
  }
}

func Cache(s string) error {
	return nil
}
