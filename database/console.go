package database

import (
  "bufio"
  "fmt"
	"io/ioutil"
  "log"
  "os"
  "rs3/security"
  "runtime/pprof"
  "strings"
)

func Console() {
  scanner := bufio.NewScanner(os.Stdin)
  fmt.Print(">>> ")
  for scanner.Scan() {
    tokens := strings.Split(scanner.Text(), " ")
    switch {

    // Quit.
    case tokens[0] == "exit":
      panic("")

    // Add user.
    case tokens[0] == "add":
      switch tokens[1] {
      case "user":
        username := tokens[2]
        password := tokens[3]
        nickname := tokens[4]
        salt := security.NewSalt()

        uid, err := security.Hash(username, salt)
        if err != nil {
          fmt.Fprintln(os.Stderr, "Error: failed to hash username.")
        }

        pwd, err := security.Hash(password, salt)
        if err != nil {
          fmt.Fprintln(os.Stderr, "Error: failed to hash username.")
        }

        err = AddUser(uid, pwd, salt, nickname, username)
        if err != nil {
          fmt.Fprintln(os.Stderr, err.Error())
        }

      case "feed":
        uid, err := StringToUid(tokens[2])
        if err != nil {
          fmt.Println("Error parsing uid:")
          fmt.Println(err)
        }
        cookie := tokens[3]
        feed := tokens[4]

        err = AddFeeds(uid, cookie, feed)
        if err != nil {
          fmt.Println("Error adding feed:")
          fmt.Println(err)
        }
        fmt.Printf("Added feed %q.\n", feed)

      case "feeds":
        uid, err := StringToUid(tokens[2])
        if err != nil {
          fmt.Println("Error parsing uid:")
          fmt.Println(err)
        }
        cookie := tokens[3]

        for _, feed := range tokens[4:] {
          err = AddFeeds(uid, cookie, feed)
          if err != nil {
            fmt.Println("Error adding feed:")
            fmt.Println(err)
          }
          fmt.Printf("Added feed %q.\n", feed)
        }
      }

    // Remove user.
    case tokens[0] == "remove":
      username := tokens[1]
      salt := Salt(username)

      uid, err := security.Hash(username, salt)
      if err != nil {
        fmt.Fprintln(os.Stderr, "Error: failed to hash username.")
      }

      err = DeleteUser(uid)
      if err != nil {
        fmt.Fprintln(os.Stderr, err.Error())
      }

    // Check a user's feeds.
    case tokens[0] == "feeds":
      uid := tokens[1]
      user, ok := db.Users[uid]
      if ok {
        sum := 0
        for _, feed := range user.Feeds {
          fmt.Println(feed)
          sum += int(feed.Unread)
        }
        fmt.Printf("\n\nTotal feeds:  %3d\nUnread items: %3d\n", len(user.Feeds), sum)
      } else {
        fmt.Println("Error: could not find user.")
      }

    // Reset a user's feeds.
    case tokens[0] == "reset":
      uid, err := StringToUid(tokens[1])
      if err != nil {
        fmt.Println("Failed to parse uid:")
        fmt.Println(err)
      }
      err = ResetUserFeeds(uid)
      if err != nil {
        fmt.Println("Failed to reset feeds:")
        fmt.Println(err)
      }

    // Update a user's feeds.
    case tokens[0] == "update":
      uid := tokens[1]
      user, ok := db.Users[uid]
      if ok {
        for _, feed := range user.Feeds {
          start := feed.Unread
          err := feed.Update()
          if err != nil {
            fmt.Println("Error while updating feed:")
            fmt.Println(err)
            break
          }
          fmt.Printf("%d new items for feed %q.\n", feed.Unread-start, feed.Title)
        }
      } else {
        fmt.Println("Error: could not find user.")
      }

    // Debug.
    case tokens[0] == "debug":
      fmt.Println(string(Debug()))
			
		// Serialise.
		case tokens[0] == "serialise":
			data, err := ioutil.ReadAll(Reader())
			if err != nil {
				fmt.Println("Error serialising database:")
				fmt.Println(err)
			} else {
				fmt.Println(string(data))
			}

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
      err := Backup(target)
      if err != nil {
        fmt.Println("Backup error: ", err)
      }

    // Restore database.
    case tokens[0] == "restore":
      origin := tokens[1]
      err := Restore(origin)
      if err != nil {
        fmt.Println("Restore error: ", err)
      }

    // Cache content file.
    case tokens[0] == "cache":
      target := tokens[1]
      err := Cache(target)
      if err != nil {
        fmt.Fprintln(os.Stderr, err.Error())
      }

    default:
      fmt.Println("Error: command not understood.")
    }
    fmt.Print(">>> ")
  }
  if err := scanner.Err(); err != nil {
    log.Panic(os.Stderr, "reading standard input:", err)
  }
}

func Cache(s string) error {
  return nil
}
