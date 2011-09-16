// Copyright (c) 2011 The Octopkg Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package octopkg

import (
	"appengine"
	"appengine/datastore"
)

// A Repository represents a package repository.
type Repository struct {
	Name        string
	Owner       string
	Description string
	PGPKeyRing  []byte
}

// A Distribution represent a single suite of a Debian-style
// repository.
type Distribution struct {
	Name        string
	CodeName    string
	Origin      string
	Description string
	LastUpdate  datastore.Time

	// Release files and signatures
	Release          []byte
	ReleaseSignature []byte
}

// Packages represents a list of packages for a given
// {distribution, arch} tuple.
type Packages struct {
	Arch   string
	Blob   appengine.BlobKey
	Size   int64
	MD5    string
	SHA1   string
	SHA256 string
}

// A Package represents a package in a Distribution.
type Package struct {
	Name     string
	Arch     string
	Version  string
	Filename string

	Data   appengine.BlobKey
	Size   int64
	MD5    string
	SHA1   string
	SHA256 string
}
