// Copyright (c) 2011 The Octopkg Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package octopkg

import (
	"gob"
	"gorilla.googlecode.com/hg/gorilla/sessions"
	"http"
	"os"
)

func init() {
	gob.Register(Flash{})
}

type Flash struct {
	Kind string
	Text string
}

// GetFlashes extracts any stored flashes from an HTTP request.
// Does not return an error when no flashes are present.
func GetFlashes(req *http.Request) (outFlashes []Flash, err os.Error) {
	flashes, err := sessions.Flashes(req)
	if err != nil && err != sessions.ErrNoFlashes {
		return nil, err
	}

	for _, f := range flashes {
		if flash, ok := f.(Flash); ok {
			outFlashes = append(outFlashes, flash)
		}
	}

	return outFlashes, nil
}
