package server

import (
  "bytes"
  "compress/gzip"
  "encoding/json"
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

  // Create template struct
  Template := new(MainTemplate)

  // Get nickname.
  Template.Nickname, err = database.Nickname(uidBytes, auth.Value)
  if err != nil {
    fmt.Println("Failed to get nickname.")
    Template.Nickname = "[UNKNOWN]"
  }

  // Prepare templates.
  t, err := template.ParseFiles(files...)
  if err != nil {
    fmt.Println("Failed to parse templates.")
    fmt.Println(err)
    return
  }

  // Go through the user's feeds.
  feeds, err := database.Feeds(uidBytes)
  if err != nil {
    fmt.Println("Failed to get feeds.")
    Template.UnreadZero = "unread zero"
  } else {
    feedItems := make([]*FeedListItem, 0, len(feeds))
    itemItems := make([]*ItemListItem, 0, 10)
    jsData := new(JSData)
    jsData.Items = make(map[string][]*JSItem)
    unread := 0
    for i, feed := range feeds {
      unread += int(feed.Unread)
      if i == 0 {
        feedItems = append(feedItems, &FeedListItem{feed.Title, " active"})
      } else {
        feedItems = append(feedItems, &FeedListItem{feed.Title, ""})
      }
      jsItems := make([]*JSItem, 0, 10)
      for j, item := range feed.Items {
        if i == 0 {
          itemItems = append(itemItems, &ItemListItem{item.Title, item.Content, feed.Title, j+1})
        }
        jsItems = append(jsItems, &JSItem{item.Title, item.Content, feed.Title})
      }
      jsData.Items[feed.Title] = jsItems
    }
    Template.Unread = unread
    buf := new(bytes.Buffer)
    // Do unread.
    if unread > 0 {
      Template.UnreadZero = "unread"
    } else {
      Template.UnreadZero = "unread zero"
    }

    // Construct feeds list.
    for _, feed := range feedItems {
      err = t.ExecuteTemplate(buf, "feeds_template.html", feed)
      if err != nil {
        fmt.Println("Failed to parse feed list items.")
        break
      }
    }
    if err == nil {
      Template.FeedsList = template.HTML(buf.String())
    }

    buf.Reset()

    // Construct items list.
    for _, item := range itemItems {
      err = t.ExecuteTemplate(buf, "items_template.html", item)
      if err != nil {
        fmt.Println("Failed to parse item list items.")
        break
      }
    }

    if err == nil {
      Template.ItemsList = template.HTML(buf.String())
    }

    buf.Reset()

    // Construct invis.
    for i := range itemItems {
      err = t.ExecuteTemplate(buf, "invis_template.html", i)
      if err != nil {
        fmt.Println("Failed to parse invis items.")
        break
      }
    }

    if err == nil {
      Template.Invis = template.HTML(buf.String())
    }

    buf.Reset()

    // Construct JS data.
    b, err := json.Marshal(jsData.Items)
    if err != nil {
      fmt.Println("Failed to parse item list items.")
    } else {
      Template.JSData = template.JS(fmt.Sprintf(jsDataString, string(b)))
    }
  }

  // Add headers
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
  Nickname   string
  Unread     int
  UnreadZero string
  FeedsList  template.HTML
  ItemsList  template.HTML
  JSData     template.JS
  Invis      template.HTML
}

type FeedListItem struct {
  Name   string
  Active string
}

type ItemListItem struct {
  Title  string
  Desc   string
  Source string
  Index  int
}

type JSData struct {
  Items map[string][]*JSItem
}

type JSItem struct {
  Title   string
  Content string
  Source  string
}

var files = []string{"server/content/html/main.html",
  "server/content/html/items_template.html",
  "server/content/html/feeds_template.html",
  "server/content/html/invis_template.html",
}

var jsDataString = `
$(".invis").on('activate', function() {
   console.log($('#' + $("li.active").attr('id').substring(5))[0]);
});
var data = %s;
$('.feed').click(function() {
	var feed = $(this)[0].innerText.replace(/\s\s*$/, '');
	var out = [];
	var len = data[feed].length;
	for (var i = 0; i < len; ++i) {
		var item = data[feed][i]
		out.push('<li><div class="item"><h3>')
		out.push(item['Title'])
		out.push('</h3><p>')
		out.push(item['Content'])
		out.push('</p><p class="text-right"><small>')
		out.push(item['Source'])
		out.push('</small></p></div></li>')
	}
	$('#items').html(out.join(''));
	$('.active').removeClass('active')
	$(this).addClass('active')
	//console.log(data[feed]);
});
`
