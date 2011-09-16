// Copyright (c) 2011 The Octopkg Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package octopkg

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

type manyHashWriter struct {
	md5Hasher    hash.Hash
	sha1Hasher   hash.Hash
	sha256Hasher hash.Hash
	w            io.Writer
	size         int64
}

func newManyHashWriter(w io.Writer) *manyHashWriter {
	return &manyHashWriter{
		md5.New(), sha1.New(), sha256.New(), w, int64(0),
	}
}

func (mhw *manyHashWriter) Write(buf []byte) (n int, err os.Error) {
	n, err = mhw.md5Hasher.Write(buf)
	if err != nil {
		return
	}
	n, err = mhw.sha1Hasher.Write(buf)
	if err != nil {
		return
	}
	n, err = mhw.sha256Hasher.Write(buf)
	if err != nil {
		return
	}
	n, err = mhw.w.Write(buf)
	if err != nil {
		return
	}
	mhw.size += int64(n)
	return
}

func (mhw *manyHashWriter) Size() int64 {
	return mhw.size
}

func (mhw *manyHashWriter) MD5() string {
	return hex.EncodeToString(mhw.md5Hasher.Sum())
}

func (mhw *manyHashWriter) SHA1() string {
	return hex.EncodeToString(mhw.sha1Hasher.Sum())
}

func (mhw *manyHashWriter) SHA256() string {
	return hex.EncodeToString(mhw.sha256Hasher.Sum())
}
