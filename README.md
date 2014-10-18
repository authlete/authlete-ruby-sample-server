authlete-ruby-sample-server
===========================

Overview
--------

A sample implementation of OAuth 2.0 server in Ruby using Authlete.
`server.rb` is the script which implements OAuth 2.0 endpoints (the
authorization endpoint and the token endpoint) and two protected
resource endpoints (`/fortune` and `/saying`) as examples. HTMLs
used by the endpoints are embedded in the script (after `__END__`).

See [Authlete Getting Started](https://www.authlete.com/authlete_getting_started.html)
for details.


License
-------

Apache License, Version 2.0


Source Download
---------------

```
git clone https://github.com/authlete/authlete-ruby-sample-server.git
```


Set Up
------

```
gem install sinatra
gem install thin
gem install rest-client
```


Configuration
-------------

After downloading the source code, open `server.rb` with a text editor and
change the values of the following global variables.

* `$SERVICE_API_KEY`
* `$SERVICE_API_SECRET`

`$SERVICE_API_KEY` and `$SERVICE_API_SECRET` are the credentials of a service
which you have created by calling Authlete's `/service/create` API.

As necessary, change the value of the following global variable, too.

* `$AUTHLETE_BASE_URL`

`$AUTHLETE_BASE_URL` is the URL of the Authlete server you use. For evaluation,
set `https://evaluation-dot-authlete.appspot.com` to the variable.


Endpoints
---------

`server.rb` implements the following endpoints.

* The top page
  - [http://localhost:4567/](http://localhost:4567/)

* The authorization endpoint
  - [http://localhost:4567/authorization](http://localhost:4567/authorization)

* The token endpoint
  - [http://localhost:4567/token](http://localhost:4567/token)

* The protected resource endpoints
  - [http://localhost:4567/fortune](http://localhost:4567/fortune)
  - [http://localhost:4567/saying](http://localhost:4567/saying)

* The redirection endpoint (for client)
  - [http://localhost:4567/callback](http://localhost:4567/callback)

Note that it is not an OAuth 2.0 server that should implement a redirection
endpoint. Instead, it is the developer of the client application who has to
prepare the redirection endpoint. However, this sample server implements an
redirection endpoint (= the last one in the list above) just to show what
a redirection endpoint receives. Please don't be confused.


Test Steps
----------

1. Run `server.rb`.

2. Access the top page ([http://localhost:4567/](http://localhost:4567/))

3. At the top page, input the client ID of your client application (which
   you have registered by calling Authlete's `/client/create` API) and
   press "Authorization Request" button, and the web browser is redirected
   to the authorization endpoint (http://localhost:4567/authorization).

4. At the authorization endpoint, press "Authorize" button, and the web
   browser is redirected to the client's redirection endpoint
   (http://localhost:4567/callback). On success, an authorization code is
   displayed in the endpoint.

5. At the redirection endpoint, input the client ID of your client
   application and press "Token Request" button, and you receive a JSON
   containing an access token.

6. Access a protected resource endpoint with the access token issued at
   the step above. For example,
   - http://localhost:4567/fortune?access_token=${ACCESS_TOKEN}
   - http://localhost:4567/saying?access_token=${ACCESS_TOKEN}

   
Note
----

The quality of this source code does not satisfy the commercial level.
Especially:

* The endpoints are not protected by TLS.

* The authorization endpoint does not support HTTP POST method
  (OpenID Connect requires it).

* The authorization endpoint does not authenticate the end-user.
  End-user authentication always succeeds as if `joe` logged in the
  service every time. Authentication Context Class Reference, Maximum
  Authentication Age and others that should be taken into consideration
  are ignored.

* The authorization endpoint always fails when the request contains
  `prompt=none`.

* 'Claims' and 'ACR' are not set in the request for
  `/auth/authorization/issue` API. They are needed when the authorization
  endpoint supports any of `response_type`s which issue an ID token.

* The token endpoint does not support "Resource Owner Password Credentials",
  so it always fails when the token request contains `grant_type=password`.


Links
-----

* [Authlete Home Page](https://www.authlete.com/)
* [Authlete Documents](https://www.authlete.com/documents.html)
* [Authlete Getting Started](https://www.authlete.com/authlete_getting_started.html)
* [Authlete Web APIs](https://www.authlete.com/authlete_web_apis.html)
