Octopkg
=======


What is it?
-----------

Octopkg is a an App Engine app that aims host various kinds of Linux-distribution package repositories.
It's written in Go (http://www.golang.org).

For now, there is only support for hosting a Debian-style repository.


Setting it up
-------------

If you wish to deploy a copy of octopkg to your own app instance, make sure you change the AppID in app.yaml.

To fetch all external dependencies, use the fetch-deps.bash script. Use clean-deps.bash to clean up the mess.


Live instance
-------------

A live instance of octopkg is running at https://octopkg.appspot.com/
