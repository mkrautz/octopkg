// Copyright (c) 2011 The Octopkg Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package octopkg

import (
	"appengine"
	"appengine-go-backports/template"
	"appengine/blobstore"
	"appengine/datastore"
	"appengine/delay"
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/openpgp"
	"crypto/openpgp/armor"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/mkrautz/goar"
	"github.com/mkrautz/godeb/control"
	"gorilla.googlecode.com/hg/gorilla/mux"
	"gorilla.googlecode.com/hg/gorilla/sessions"
	"http"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var tmplSet = template.SetMust(template.ParseTemplateFiles(
	"templates/topbar.html",
	"templates/flashes.html",
	"templates/modals.html",
	"templates/head.html",
	"templates/home.html",
	"templates/manage.html",
	"templates/manage-repo.html",
	"templates/manage-dist.html",
	"templates/repotable.html",
))

var (
	generateRepoKeysTask = delay.Func("generateRepoKeys", generateRepoKeysHandler)
	updateRepoTask = delay.Func("updateRepo", updateRepoHandler)
)

func init() {
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/manage", manageHandler)
	mux.HandleFunc("/manage/create-repo", repoCreationHandler)
	mux.HandleFunc("/manage/{repo}", manageRepoHandler)
	mux.HandleFunc("/manage/{repo}/create-dist", distCreationHandler)
	mux.HandleFunc("/manage/{repo}/{distribution}", manageDistHandler)
	mux.HandleFunc("/manage/{repo}/{distribution}/upload-pkg", uploadPkgHandler)

	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/create", accountCreateHandler)

	mux.HandleFunc("/~{username}", userPageHandler)

	mux.HandleFunc("/{repo}", repoHandler)
	mux.HandleFunc("/{repo}/pubkey.pgp", repoPubKeyHandler)
	mux.HandleFunc("/{repo}/apt/dists/{distribution}/main/binary-{arch}/Packages", debianPackages)
	mux.HandleFunc("/{repo}/apt/dists/{distribution}/Release", debianRelease)
	mux.HandleFunc("/{repo}/apt/dists/{distribution}/Release.gpg", debianReleasePgp)
	mux.HandleFunc("/{repo}/apt/pkgs/{distribution}/{filename}", debianFileHandler)

	http.Handle("/", mux.DefaultRouter)
}

// State that we expect a number of vars to be present
func expectVars(vars mux.RouteVars, names ...string) os.Error {
	for _, name := range names {
		if _, exists := vars[name]; !exists {
			return fmt.Errorf("expected var: %v", name)
		}
	}
	return nil
}

// The home handler.
// Handles requests for the front page.
//
// Path:            /
// Expected vars:   None
// Requires login:  No
func homeHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	args := struct {
		User    *User
		Flashes []Flash
		Repos   []*Repository
	}{}

	user, err := GetUser(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	args.User = user

	flashes, err := GetFlashes(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	args.Flashes = flashes

	sessions.Save(req, rw)

	query := datastore.NewQuery("Repository")
	_, err = query.GetAll(ctx, &args.Repos)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	err = tmplSet.Execute(rw, "home.html", args)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
}

// The manage handler.
// Presents a logged-in user with all his repositories and allows him to manage them. 
//
// Path:            /manage
// Expected vars:   None
// Requires login:  Yes
func manageHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	args := struct {
		User    *User
		Flashes []Flash
		Repos   []*Repository
	}{}

	user, err := GetUser(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	args.User = user

	// For logged-in users only
	if args.User == nil {
		http.Error(rw, "page not found", 404)
		return
	}

	flashes, err := GetFlashes(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	args.Flashes = flashes
	sessions.Save(req, rw)

	// Get all of the logged-in user's repositories
	query := datastore.NewQuery("Repository").Filter("Owner =", user.Username)
	_, err = query.GetAll(ctx, &args.Repos)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	err = tmplSet.Execute(rw, "manage.html", args)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
}

// The repo creation handler.
// A POST request is made to this handler by users to create new Repository instances.
//
// Path:            /manage/create-repo
// Expected vars:   None
// Requires login:  Yes
func repoCreationHandler(rw http.ResponseWriter, req *http.Request) {
	// Only allow POST requests
	if req.Method != "POST" {
		http.Error(rw, "handler requires POST requests", 404)
		return
	}

	ctx := appengine.NewContext(req)

	// We require a logged in user to create a new repo.
	user, err := GetUser(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	// Repository creation requires a logged-in user
	if user == nil {
		http.Error(rw, "forbidden", 403)
		return
	}

	repo := Repository{}
	repo.Name = req.FormValue("name")
	repo.Description = req.FormValue("description")
	repo.Owner = user.Username

	match, _ := regexp.MatchString(`^[a-z][a-z\-]*$`, repo.Name)
	if !match {
		http.Error(rw, "invalid repo name", 500)
		return
	}

	err = datastore.RunInTransaction(ctx, func(ctx appengine.Context) os.Error {
		key := datastore.NewKey("Repository", repo.Name, 0, nil)

		// Is there already a repository with this name? Don't allow us to overwrite it.
		existingRepo := Repository{}
		err := datastore.Get(ctx, key, &existingRepo)
		if err == datastore.ErrNoSuchEntity {
			_, err := datastore.Put(ctx, datastore.NewKey("Repository", repo.Name, 0, nil), &repo)
			if err != nil {
				return err
			}
		} else {
			if err == nil {
				return os.NewError("repository already exists")
			} else {
				return err
			}
		}
		return nil
	})
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	generateRepoKeysTask.Call(ctx, repo.Name)

	http.Redirect(rw, req, "/manage", 307)
}

// Generate or regenerate the cryptographic keys for a given repository.
func generateRepoKeysHandler(ctx appengine.Context, repoName string) os.Error {
	repo := Repository{}
	key := datastore.NewKey("Repository", repoName, 0, nil)
	err := datastore.Get(ctx, key, &repo)
	if err != nil {
		return fmt.Errorf("unable to generate keys: %v", err)
	}

	// Create a PGP signing keypair for the new repo
	entity, err := openpgp.NewEntity(rand.Reader, time.Seconds(), fmt.Sprintf("octopkg: %v", repo.Name), "", "")
	if err != nil {
		return fmt.Errorf("unable to create pgp entity: %v", err)
	}
	buf := new(bytes.Buffer)
	err = entity.SerializePrivate(buf)
	if err != nil {
		return fmt.Errorf("unable to serialize entity: %v", err)
	}
	repo.PGPKeyRing = buf.Bytes()

	// Put the modified repo
	_, err = datastore.Put(ctx, key, &repo)
	if err != nil {
		return fmt.Errorf("unable to put upadted repo: %v", err)
	}

	return nil
}

// Manage a specific repository.
// Presents the user with a list of distributions that are part of the the repository, and allows
// him/her to manage them (create, delete, etc.)
//
// Path:            /manage/{repo}
// Expected vars:   repo
// Requires login:  Requires login and ownership of the repository.
func manageRepoHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	args := struct {
		User  *User
		Repo  Repository
		Dists []*Distribution
	}{}

	user, err := GetUser(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	args.User = user

	vars := mux.Vars(req)
	err = expectVars(vars, "repo")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]

	key := datastore.NewKey("Repository", repoName, 0, nil)
	err = datastore.Get(ctx, key, &args.Repo)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	query := datastore.NewQuery("Distribution").Ancestor(key)
	_, err = query.GetAll(ctx, &args.Dists)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	// Make sure that only the owner of the repository
	// can see this.
	if user == nil || user.Username != args.Repo.Owner {
		http.Error(rw, "page not found", 404)
		return
	}

	err = tmplSet.Execute(rw, "manage-repo.html", args)
	if err != nil {
		ctx.Infof("%v", err)
		http.Error(rw, err.String(), 500)
		return
	}
}

// Create a distribution.
// Users POST this URL to create new distributions.
//
// Path:            /manage/{repo}/create-dist
// Expected vars:   repo
// Requires login:  Requires login and ownership of the repository.
func distCreationHandler(rw http.ResponseWriter, req *http.Request) {
	// Only allow POST requests
	if req.Method != "POST" {
		http.Error(rw, "handler requires POST requests", 404)
		return
	}

	user, err := GetUser(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err = expectVars(vars, "repo")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]

	// Look up the repository
	repo := Repository{}
	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	err = datastore.Get(ctx, repoKey, &repo)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	// Check that the user is logged in, and that the logged-in user
	// is the owner of the repository we're about to create a distribution
	// for.
	if user == nil || repo.Owner != user.Username {
		http.Error(rw, "forbidden", 403)
		return
	}

	dist := Distribution{}
	dist.Name = req.FormValue("name")
	dist.Description = req.FormValue("description")

	match, _ := regexp.MatchString(`^[a-z][a-z\-]*$`, dist.Name)
	if !match {
		http.Error(rw, "invalid distribution name", 500)
		return
	}

	err = datastore.RunInTransaction(ctx, func(ctx appengine.Context) os.Error {
		key := datastore.NewKey("Distribution", dist.Name, 0, repoKey)
		// Is there already a distribution with this name and ancestor? Don't allow us to overwrite it.
		existingDist := Distribution{}
		err := datastore.Get(ctx, key, &existingDist)
		if err == datastore.ErrNoSuchEntity {
			_, err := datastore.Put(ctx, key, &dist)
			if err != nil {
				return err
			}
		} else {
			if err == nil {
				return os.NewError("repository already exists")
			} else {
				return err
			}
		}
		return nil
	})
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	http.Redirect(rw, req, "/manage/"+repo.Name, 307)
}

// Manage a distribution.
// Shows the user a short text telling them how package uploads work.
//
// Path:            /manage/{repo}/{distribution}
// Expected vars:   repo, distribution
// Requires login:  Requires login and ownership of the repository.
func manageDistHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err := expectVars(vars, "repo", "distribution")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]
	distName := vars["distribution"]

	// Args is the argument struct for our template rendering
	args := struct {
		User *User
		Repo Repository
		Dist Distribution
	}{}

	user, err := GetUser(req)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	args.User = user

	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	err = datastore.Get(ctx, repoKey, &args.Repo)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	distKey := datastore.NewKey("Distribution", distName, 0, repoKey)
	err = datastore.Get(ctx, distKey, &args.Dist)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	// Check for nil user (not logged in), and that the user attempting
	// to access the repo is the owner.
	if args.User == nil || args.Repo.Owner != args.User.Username {
		http.Error(rw, "forbidden", 403)
		return
	}

	err = tmplSet.Execute(rw, "manage-dist.html", args)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
}

// Handle a new package upload to a distribution.
//
// Path:            /manage/{repo}/{distribution}/upload-pkg
// Expected vars:   repo, distribution
// Requires login:  Requires login and ownership of the repository.
func uploadPkgHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(rw, "handler requires POST requests", 404)
		return
	}

	user, err := CheckBasicAuth(req)
	if err != nil {
		http.Error(rw, "forbidden", 403)
		return
	}
	if user == nil {
		http.Error(rw, "forbidden", 403)
		return
	}

	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err = expectVars(vars, "repo", "distribution")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	repoName := vars["repo"]
	distName := vars["distribution"]

	// Args is the argument struct for our template rendering
	args := struct {
		Repo Repository
		Dist Distribution
	}{}

	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	err = datastore.Get(ctx, repoKey, &args.Repo)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	if user == nil || args.Repo.Owner != user.Username {
		http.Error(rw, "forbidden", 403)
		return
	}

	distKey := datastore.NewKey("Distribution", distName, 0, repoKey)
	err = datastore.Get(ctx, distKey, &args.Dist)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	blob, err := blobstore.Create(ctx, "application/x-deb")
	if err != nil {
		http.Error(rw, err.String(), 500)
	}

	md5er := md5.New()
	sha1er := sha1.New()
	sha256er := sha256.New()
	pr, pw := io.Pipe()
	controlFile := []byte{}
	foundControl := false

	go func() {
		ar := ar.NewReader(pr)
		hdr, err := ar.Next()
		if err != nil {
			pr.CloseWithError(err)
			return
		}

		if hdr.Name == "debian-binary" && hdr.Size == 4 {
			buf := make([]byte, 4)
			_, err = io.ReadFull(ar, buf)
			if err != nil {
				pr.CloseWithError(err)
				return
			}
			if string(buf) != "2.0\n" {
				pr.CloseWithError(os.NewError("debian binary version not 2.0"))
				return
			}
		} else {
			pr.CloseWithError(os.NewError("not a debian package"))
			return
		}

		hdr, err = ar.Next()
		if err != nil {
			pr.CloseWithError(err)
			return
		}
		if hdr.Name == "control.tar.gz" {
			zr, err := gzip.NewReader(ar)
			if err != nil {
				pr.CloseWithError(err)
				return
			}
			controlReader := tar.NewReader(zr)
			for {
				hdr, err := controlReader.Next()
				if err == os.EOF {
					break
				} else if err != nil {
					pr.CloseWithError(err)
					return
				}
				if hdr.Name == "./control" {
					foundControl = true
					controlFile, err = ioutil.ReadAll(controlReader)
					if err != nil {
						pr.CloseWithError(err)
						return
					}
					break
				}
			}
		} else {
			pr.CloseWithError(os.NewError("not a debian package"))
			return
		}

		err = pr.Close()
		if err != nil {
			return
		}
	}()

	chunk := make([]byte, 4096)
	pkgSize := int64(0)
	donePipe := false
	for {
		nread, err := req.Body.Read(chunk)
		if err == os.EOF {
			break
		} else if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}
		pkgSize += int64(nread)

		_, err = blob.Write(chunk[0:nread])
		if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}

		_, err = md5er.Write(chunk[0:nread])
		if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}

		_, err = sha1er.Write(chunk[0:nread])
		if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}

		_, err = sha256er.Write(chunk[0:nread])
		if err != nil {
			http.Error(rw, err.String(), 500)
			return
		}

		if !donePipe {
			_, err = pw.Write(chunk[0:nread])
			if err == os.EPIPE {
				donePipe = true
			} else if err != nil {
				http.Error(rw, err.String(), 500)
				return
			}
		}
	}

	if !foundControl {
		http.Error(rw, "no control file found in archive", 500)
		return
	}

	err = blob.Close()
	blobKey, err := blob.Key()
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	kvp, err := control.Parse(bytes.NewBuffer(controlFile))
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	kvm := control.KeyValueMap(kvp)
	pkg := Package{}

	if _, exists := kvm["Package"]; !exists {
		http.Error(rw, "missing Package key in control file", 500)
		return
	}

	if _, exists := kvm["Version"]; !exists {
		http.Error(rw, "missing Version key in control file", 500)
		return
	}

	if _, exists := kvm["Architecture"]; !exists {
		http.Error(rw, "missing Architecture key in control file", 500)
		return
	}

	pkg.Name = kvm["Package"]
	pkg.Version = kvm["Version"]
	pkg.Arch = kvm["Architecture"]
	pkg.Filename = pkg.Name + "_" + pkg.Version + "_" + pkg.Arch + ".deb"

	pkg.Size = pkgSize
	pkg.Data = blobKey
	pkg.MD5 = hex.EncodeToString(md5er.Sum())
	pkg.SHA1 = hex.EncodeToString(sha1er.Sum())
	pkg.SHA256 = hex.EncodeToString(sha256er.Sum())

	pkgKey := datastore.NewKey("Package", pkg.Name+"_"+pkg.Arch, 0, distKey)
	_, err = datastore.Put(ctx, pkgKey, &pkg)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	// Make sure we update the packages list
	updateRepoTask.Call(ctx, args.Repo.Name, args.Dist.Name)

	rw.Write([]byte(fmt.Sprintf("Uploaded %v to repo '%v' distribution '%v'\n", pkg.Filename, args.Repo.Name, args.Dist.Name)))
}

// Update the packages for a given distribution
func updateRepoHandler(ctx appengine.Context, repoName string, distName string) {
	var (
		Repo Repository
		Dist Distribution
	)

	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	err := datastore.Get(ctx, repoKey, &Repo)
	if err != nil {
		ctx.Errorf("unable to create new key: %v", err.String())
		return
	}

	distKey := datastore.NewKey("Distribution", distName, 0, repoKey)
	err = datastore.Get(ctx, distKey, &Dist)
	if err != nil {
		ctx.Errorf("unable to create new key: %v", err.String())
		return
	}

	pkgs := []*Package{}
	_, err = datastore.NewQuery("Package").Ancestor(distKey).GetAll(ctx, &pkgs)
	if err != nil {
		ctx.Errorf("unable to create new query: %v", err.String())
		return
	}

	archWriter := make(map[string]*blobstore.Writer)
	mhwArchWriter := make(map[string]*manyHashWriter)
	for _, pkg := range pkgs {
		pkgList, exists := mhwArchWriter[pkg.Arch]
		if !exists {
			blobWriter, err := blobstore.Create(ctx, "")
			if err != nil {
				ctx.Errorf("unable to create new blob: %v", err)
				return
			}
			archWriter[pkg.Arch] = blobWriter
			pkgList = newManyHashWriter(blobWriter)
			mhwArchWriter[pkg.Arch] = pkgList
		}

		buf := bufio.NewWriter(pkgList)
		_, err = buf.WriteString("Package: " + pkg.Name + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("Priority: optional\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("Architecture: " + pkg.Arch + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("Version: " + pkg.Version + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("Filename: pkgs/" + Dist.Name + "/" + pkg.Filename + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("Size: " + strconv.Itoa64(pkg.Size) + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("MD5sum: " + pkg.MD5 + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("SHA1: " + pkg.SHA1 + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("SHA256: " + pkg.SHA256 + "\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("Description: None\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		_, err = buf.WriteString("\n")
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		err = buf.Flush()
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
	}

	archKeys := make(map[string]appengine.BlobKey)
	for arch, writer := range archWriter {
		err = writer.Close()
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		blobKey, err := writer.Key()
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
		archKeys[arch] = blobKey
	}

	var newPackagesFiles []*Packages
	err = datastore.RunInTransaction(ctx, func(tc appengine.Context) os.Error {
		// First, remove all existing Packages lists for this Distribution
		existingKeys, err := datastore.NewQuery("Packages").Ancestor(distKey).KeysOnly().GetAll(ctx, nil)
		if err != nil {
			return err
		}
		err = datastore.DeleteMulti(ctx, existingKeys)
		if err != nil {
			return err
		}

		// Create new packages listings
		for arch, blobKey := range archKeys {
			mhw := mhwArchWriter[arch]

			pkgs := Packages{}
			pkgs.Arch = arch
			pkgs.Blob = blobKey
			pkgs.Size = mhw.Size()
			pkgs.MD5 = mhw.MD5()
			pkgs.SHA1 = mhw.SHA1()
			pkgs.SHA256 = mhw.SHA256()

			key := datastore.NewKey("Packages", pkgs.Arch, 0, distKey)
			_, err = datastore.Put(ctx, key, &pkgs)
			if err != nil {
				return err
			}

			newPackagesFiles = append(newPackagesFiles, &pkgs)
		}

		return nil
	})
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}

	// Now, it's time to update the Release file and its signature
	now := time.Seconds()
	Dist.LastUpdate = datastore.SecondsToTime(now)
	utcTime := time.SecondsToUTC(now)

	buf := new(bytes.Buffer)
	_, err = buf.WriteString("Origin: " + Dist.Origin + "\n")
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	_, err = buf.WriteString("Label: " + Dist.Description + "\n")
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	_, err = buf.WriteString("Suite: " + Dist.Name + "\n")
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	_, err = buf.WriteString("Date: " + utcTime.Format(time.RFC1123) + "\n")
	if err != nil {
		ctx.Errorf("%v, err")
		return
	}
	_, err = buf.WriteString("Architectures:")
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	for arch, _ := range archKeys {
		_, err = buf.WriteString(" " + arch)
		if err != nil {
			ctx.Errorf("%v", err)
			return
		}
	}
	_, err = buf.WriteString("\nComponents: main\n")
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	_, err = buf.WriteString("MD5Sum:\n")
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	for _, pkgs := range newPackagesFiles {
		_, err = buf.WriteString(" " + pkgs.MD5 + " " + strconv.Itoa64(pkgs.Size) + " main/binary-" + pkgs.Arch + "/Packages")
	}

	Dist.Release = buf.Bytes()

	// And sign it..
	el, err := openpgp.ReadKeyRing(bytes.NewBuffer(Repo.PGPKeyRing))
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	if len(el) == 0 {
		ctx.Errorf("no entities found!")
		return
	}
	entity := el[0]
	signature := new(bytes.Buffer)
	err = openpgp.DetachSign(signature, entity, bytes.NewBuffer(Dist.Release))
	if err != nil {
		ctx.Errorf("unable to sign releases!")
		return
	}
	armoredSignature := new(bytes.Buffer)
	wc, err := armor.Encode(armoredSignature, openpgp.SignatureType, map[string]string{
		"Version": "octopkg/devel",
	})
	if err != nil {
		ctx.Errorf("unable to armor signature!")
		return
	}
	_, err = io.Copy(wc, signature)
	if err != nil {
		ctx.Errorf("unable to write siganture to be armored")
		return
	}
	err = wc.Close()
	if err != nil {
		ctx.Errorf("unable to close armorer")
		return
	}
	Dist.ReleaseSignature = armoredSignature.Bytes()

	_, err = datastore.Put(ctx, distKey, &Dist)
	if err != nil {
		ctx.Errorf("%v", err)
	}
}

// Show the contents of a Repository
//
// Path:            /{repo}
// Expected vars:   repo
// Requires login:  No
func repoHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	err := expectVars(vars, "repo")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repo := vars["repo"]

	rw.Write([]byte(repo))
}

// Request the public PGP key for the given Repository
//
// Path:            /{repo}/pubkey.pgp
// Expected vars:   repo
// Requires login:  No
func repoPubKeyHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err := expectVars(vars, "repo")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]
	repoKey := datastore.NewKey("Repository", repoName, 0, nil)

	repo := Repository{}
	err = datastore.Get(ctx, repoKey, &repo)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	// Load the keyring
	el, err := openpgp.ReadKeyRing(bytes.NewBuffer(repo.PGPKeyRing))
	if err != nil {
		ctx.Errorf("%v", err)
		return
	}
	if len(el) == 0 {
		ctx.Errorf("no entities found!")
		return
	}
	entity := el[0]

	pubKey := new(bytes.Buffer)
	err = SerializePublicEntity(entity, pubKey)
	if err != nil {
		http.Error(rw, fmt.Sprintf("unable to serialize pubkey: %v", err), 500)
		return
	}

	wc, err := armor.Encode(rw, openpgp.PublicKeyType, map[string]string{
		"Version": "octopkg/devel",
	})
	if err != nil {
		ctx.Errorf("unable to armor signature!")
		return
	}
	_, err = io.Copy(wc, bytes.NewBuffer(pubKey.Bytes()))
	if err != nil {
		ctx.Errorf("unable to write siganture to be armored")
		return
	}
	err = wc.Close()
	if err != nil {
		ctx.Errorf("unable to close armorer")
		return
	}
}

// Return a list of packages for the given arch of the Distribution found in the Repository.
//
// Path:            /{repo}/apt/dists/{distribution}/main/binary-{arch}/Packages
// Expected vars:   repo, distribution, arch
// Requires login:  No
func debianPackages(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err := expectVars(vars, "repo", "distribution", "arch")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]
	distName := vars["distribution"]
	arch := vars["arch"]

	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	distKey := datastore.NewKey("Distribution", distName, 0, repoKey)
	packages := []*Packages{}

	_, err = datastore.NewQuery("Packages").Ancestor(distKey).Filter("Arch =", arch).GetAll(ctx, &packages)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	if len(packages) == 0 {
		http.Error(rw, "no packges", 404)
		return
	}

	reader := blobstore.NewReader(ctx, packages[0].Blob)
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}

	_, err = io.Copy(rw, reader)
	if err != nil {
		ctx.Errorf("unable to complete copy: %v", err)
		return
	}
}

// Returns a Release file for the Distribution.
//
// The Release file contains metadata about the distribution.
// The intention is that this file can be signed by using asymmetric crypto, and
// that this signature can cover all of the current release of the distribution.
// Thus, this file must
// contain digests of all other important files. 
// Since this file contains the digest of the Packages file, all packages are
// implcitly signed by 
//
// Path:            /{repo}/apt/dists/{distribution}/Release
// Expected vars:   repo, distribution
// Requires login:  No
func debianRelease(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err := expectVars(vars, "repo", "distribution")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]
	distName := vars["distribution"]
	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	distKey := datastore.NewKey("Distribution", distName, 0, repoKey)

	var Dist Distribution
	err = datastore.Get(ctx, distKey, &Dist)
	if err != nil {
		ctx.Errorf("unable to create new key: %v", err.String())
		return
	}

	_, err = rw.Write(Dist.Release)
	if err != nil {
		ctx.Errorf("unable to write relase: %v", err)
	}
}

// Returns the signature for the Release file for the Distribution.
//
// Path:            /{repo}/apt/dists/{distribution}/Release.gpg
// Expected vars:   repo, distribution
// Requires login:  No
func debianReleasePgp(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err := expectVars(vars, "repo", "distribution")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]
	distName := vars["distribution"]
	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	distKey := datastore.NewKey("Distribution", distName, 0, repoKey)

	var Dist Distribution
	err = datastore.Get(ctx, distKey, &Dist)
	if err != nil {
		ctx.Errorf("unable to create new key: %v", err.String())
		return
	}

	_, err = rw.Write(Dist.ReleaseSignature)
	if err != nil {
		ctx.Errorf("unable to write relase: %v", err)
	}
}

// Streams the given file to the downloader.
//
// Path:            /{repo}/apt/pkgs/{distribution}/{filename}
// Expected vars:   repo, distribution
// Requires login:  No
func debianFileHandler(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	vars := mux.Vars(req)
	err := expectVars(vars, "repo", "distribution", "filename")
	if err != nil {
		http.Error(rw, err.String(), 500)
		return
	}
	repoName := vars["repo"]
	distName := vars["distribution"]
	fileName := vars["filename"]

	if !strings.HasSuffix(fileName, ".deb") {
		http.Error(rw, "no such package", 404)
		return
	}

	// Split the requested fileName into name, version, arch
	fileName = fileName[0 : len(fileName)-4]
	components := strings.Split(fileName, "_", -1)
	if len(components) != 3 {
		ctx.Errorf("filename does not have 3 components after _ split")
		http.Error(rw, "no such package", 404)
		return
	}

	pkgName := components[0]
	version := components[1]
	arch := components[2]

	repoKey := datastore.NewKey("Repository", repoName, 0, nil)
	distKey := datastore.NewKey("Distribution", distName, 0, repoKey)
	pkgKey := datastore.NewKey("Package", pkgName+"_"+arch, 0, distKey)

	pkg := Package{}
	err = datastore.Get(ctx, pkgKey, &pkg)
	if err != nil {
		ctx.Errorf("%v", err)
		http.Error(rw, "no such package", 404)
		return
	}

	// Check that the returned version matches the expected one
	if pkg.Version != version {
		http.Error(rw, "no such package", 404)
		return
	}

	reader := blobstore.NewReader(ctx, pkg.Data)
	_, err = io.Copy(rw, reader)
	if err != nil {
		ctx.Errorf("unable to copy: %v", err)
		return
	}
}

// Presents a user's personal page.
//
// Path:            /~{username}
// Expected vars:   username
// Requires login:  No
func userPageHandler(rw http.ResponseWriter, req *http.Request) {
	http.Error(rw, "forbidden", 403)
	return
}
