#!/bin/bash

./clean-deps.bash

git clone https://github.com/mkrautz/godeb github.com/mkrautz/godeb
git clone https://github.com/mkrautz/goar github.com/mkrautz/goar
hg clone https://appengine-go-backports.googlecode.com/hg appengine-go-backports
hg clone -u go.r58 https://gorilla.googlecode.com/ gorilla.googlecode.com/hg
rm -rf gorilla.googlecode.com/hg/examples