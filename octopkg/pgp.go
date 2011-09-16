// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package octopkg

import (
	"crypto/openpgp"
	"io"
	"os"
)

// SerializePublicEntity writes the public part of the given Entity to w. (No private
// key material will be output).
// 
// Imported from the Go repo @ 9690:2bd37ba2bcbb
func SerializePublicEntity(e *openpgp.Entity, w io.Writer) os.Error {
	err := e.PrimaryKey.Serialize(w)
	if err != nil {
		return err
	}
	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return err
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return err
		}
		for _, sig := range ident.Signatures {
			err = sig.Serialize(w)
			if err != nil {
				return err
			}
		}
	}
	for _, subkey := range e.Subkeys {
		err = subkey.PublicKey.Serialize(w)
		if err != nil {
			return err
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
}
