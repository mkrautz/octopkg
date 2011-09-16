// Copyright (c) 2011 The Octopkg Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package octopkg

import (
	"appengine"
	"appengine/datastore"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"gorilla.googlecode.com/hg/gorilla/sessions"
	"http"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// A User represents a registered user
type User struct {
	Username string
	Email    string
	Password string
}

// GetUser returns the currently logged in user.
func GetUser(req *http.Request) (*User, os.Error) {
	ctx := appengine.NewContext(req)

	session, err := sessions.Session(req)
	if err != nil {
		return nil, err
	}

	val, exists := session["user"]
	if !exists {
		ctx.Infof("No user key found in session data")
		return nil, nil
	}
	username, ok := val.(string)
	if !ok {
		return nil, nil
	}

	user := User{}
	key := datastore.NewKey("User", username, 0, nil)
	err = datastore.Get(ctx, key, &user)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func SaltPassword(salt []byte, pw string) (string, os.Error) {
	hasher := sha256.New()
	_, err := hasher.Write(salt)
	if err != nil {
		return "", err
	}
	_, err = hasher.Write([]byte(pw))
	if err != nil {
		return "", err
	}
	_, err = hasher.Write(salt)
	if err != nil {
		return "", err
	}
	return "sha256$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(hasher.Sum()), nil
}

// Determine whether the request contains an Authorization header
// for use with Basic auth.  Then look up whether the given username
// and password combination is valid for a given user.
func CheckBasicAuth(req *http.Request) (*User, os.Error) {
	auth := req.Header.Get("Authorization")
	parts := strings.Split(auth, " ", -1)
	if len(parts) != 2 {
		return nil, os.NewError("auth: Split Authorization header does not contain two parts")
	}

	if parts[0] != "Basic" {
		return nil, os.NewError("auth: Authorization is not basic auth")
	}

	usernamePasswordPair, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, os.NewError("auth: Unable to base64-decode Authorization header")
	}

	parts = strings.Split(string(usernamePasswordPair), ":", -1)
	if len(parts) != 2 {
		return nil, os.NewError("auth: unable to split username-password pair into two parts (couldn't find :)")
	}

	username := parts[0]
	password := parts[1]

	ctx := appengine.NewContext(req)
	user := User{}
	key := datastore.NewKey("User", username, 0, nil)
	err = datastore.Get(ctx, key, &user)
	if err != nil {
		return nil, err
	}

	if user.CheckPassword(password) {
		return &user, nil
	}

	return nil, nil
}

func (u *User) SetPassword(pw string) os.Error {
	salt := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}
	password, err := SaltPassword(salt, pw)
	if err != nil {
		return err
	}
	u.Password = password
	return nil
}

func (u *User) CheckPassword(pw string) bool {
	split := strings.Split(u.Password, "$", -1)
	if len(split) != 3 {
		return false
	}
	salt, err := hex.DecodeString(split[1])
	if err != nil {
		return false
	}
	password, err := SaltPassword(salt, pw)
	if err != nil {
		return false
	}
	return u.Password == password
}

// Get the Gravatar URL for a user
func (u *User) GravatarURL(size int) string {
	md5er := md5.New()
	email := strings.ToLower(strings.TrimSpace(u.Email))
	hexMD5 := "0000000000000000"
	_, err := md5er.Write([]byte(email))
	if err != nil {
		// fixme(mkrautz) log this?
	} else if err == nil {
		hexMD5 = hex.EncodeToString(md5er.Sum())
	}
	return "//www.gravatar.com/avatar/" + hexMD5 + "?s=" + strconv.Itoa(size)
}

func loginHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)

	session, err := sessions.Session(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	if _, exists := session["user"]; exists {
		http.Error(rw, "page not found", 404)
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	user := User{}
	key := datastore.NewKey("User", username, 0, nil)
	err = datastore.Get(ctx, key, &user)
	if err == datastore.ErrNoSuchEntity {
		http.Redirect(rw, req, "/", 307)
		return
	}

	if user.CheckPassword(password) {
		session["user"] = user.Username
		sessions.Save(req, rw)
		http.Redirect(rw, req, "/", 307)
		return
	}

	http.Error(rw, "page not found", 404)
}

func logoutHandler(rw http.ResponseWriter, req *http.Request) {
	if session, err := sessions.Session(req); err == nil {
		if _, exists := session["user"]; exists {
			session["user"] = "", false
			sessions.Save(req, rw)
			http.Redirect(rw, req, "/", 307)
			return
		}
	}

	http.Error(rw, "no such page", 404)
	return
}

func accountCreateHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)

	// Get session handle
	session, err := sessions.Session(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	// Check for already logged-in user
	if _, exists := session["user"]; exists {
		http.Error(rw, "page not found", 404)
		return
	}

	username := strings.ToLower(strings.TrimSpace(req.FormValue("username")))
	password := req.FormValue("password")
	email := strings.TrimSpace(req.FormValue("email"))

	user := User{}

	// Check username length
	if len(username) < 3 {
		_, err := sessions.AddFlash(req, Flash{"error", "Username too short"})
		if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}
		sessions.Save(req, rw)
		http.Redirect(rw, req, "/", 307)
		return
	}

	// Check if we're only ASCII alphanumeric
	match, err := regexp.MatchString("^[a-z0-9]*$", username)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	if !match {
		_, err := sessions.AddFlash(req, Flash{"error", "Username contains invalid characters"})
		if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}
		sessions.Save(req, rw)
		http.Redirect(rw, req, "/", 307)
		return
	}

	user.Username = username
	user.Email = email

	// Check password length, and set it if is of a sufficient length
	if len(password) <= 6 {
		_, err := sessions.AddFlash(req, Flash{"error", "Password too short"})
		if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}
		sessions.Save(req, rw)
		http.Redirect(rw, req, "/", 307)
		return
	}

	user.SetPassword(password)

	key := datastore.NewKey("User", user.Username, 0, nil)
	err = datastore.RunInTransaction(ctx, func(ctx appengine.Context) os.Error {
		err := datastore.Get(ctx, key, &user)
		if err == datastore.ErrNoSuchEntity {
			_, err = datastore.Put(ctx, key, &user)
			if err != nil {
				return err
			}
		} else if err == nil {
			return os.NewError("user already exists")
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	sessions.AddFlash(req, Flash{"success", "Successfully created account. Welcome " + user.Username + "!"})
	session["user"] = user.Username
	sessions.Save(req, rw)
	http.Redirect(rw, req, "/", 307)
}
