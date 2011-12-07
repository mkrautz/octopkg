#!/bin/bash

./clean-deps.bash

git clone https://github.com/mkrautz/godeb github.com/mkrautz/godeb
git clone https://github.com/mkrautz/goar github.com/mkrautz/goar
hg clone -u go.r60 https://gorilla.googlecode.com/ gorilla.googlecode.com/hg
rm -rf gorilla.googlecode.com/hg/examples
rm -rf gorilla.googlecode.com/hg/lib

hg clone -u release.r60.2 https://go.googlecode.com/hg/go go
mkdir -p crypto
mv go/src/pkg/crypto/openpgp crypto/
rm -rf go
