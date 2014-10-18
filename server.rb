#!/usr/bin/env ruby
#
# == License
#
#   Copyright (C) 2014 Authlete, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#
# == Overview
#
#   This is a sample implementation of OAuth 2.0 server using Authlete.
#
#
# == Set Up
#
#   gem install sinatra
#   gem install thin
#   gem install rest-client
#
#
# == Configuration
#
#   Change the following global variables in this script.
#
#   * $AUTHLETE_BASE_URL
#   * $SERVICE_API_KEY
#   * $SERVICE_API_SECRET
#
#
# == Endpoints
#
#   * The top page
#       http://localhost:4567/
#
#   * The authorization endpoint
#       http://localhost:4567/authorization
#
#   * The token endpoint
#      http://localhost:4567/token
#
#   * The protected resource endpoints
#      http://localhost:4567/fortune
#      http://localhost:4567/saying
#
#   * The redirection endpoint (for client)
#      http://localhost:4567/callback
#
#
# == Test Steps
#
#   (1) Run this script.
#
#   (2) Access the top page (http://localhost:4567/).
#
#   (3) At the top page, input the client ID of your client
#       application and press "Authorization Request" button,
#       and the web browser is redirected to the authorization
#       endpoint (http://localhost:4567/authorization).
#
#   (4) At the authorization endpoint, press "Authorize" button,
#       and the web browser is redirected to the client's
#       redirection endpoint (http://localhost:4567/callback).
#       On success, an authorization code is displayed in the
#       endpoint.
#
#   (5) At the redirection endpoint, input the client ID of
#       your client application and press "Token Request" button,
#       and you receive a JSON containing an access token.
#
#   (6) Access a protected resource endpoint with the access
#       token issued at the step above. For example,
#
#         http://localhost:4567/fortune?access_token=${ACCESS_TOKEN}
#         http://localhost:4567/saying?access_token=${ACCESS_TOKEN}
#
#
# == Note
#
#   The quality of this source code does not satisfy the
#   commercial level. Especially,
#
#   * The endpoints are not protected by TLS.
#
#   * The authorization endpoint does not support POST
#     (OpenID Connect requires it).
#
#   * The authorization endpoint does not authenticate the
#     end-user. (End-user authentication always succeeds
#     as if 'joe' logged in the service every time.)
#     Authentication Context Class Reference, Maximum
#     Authentication Age and others that should be taken
#     into consideration are ignored.
#
#   * The authorization endpoint always fails when the
#     request contains "prompt=none".
#
#   * 'Claims' and 'ACR' are not set in the request for
#     /auth/authorization/issue API.
#
#   * The token endpoint does not support "Resource Owner
#     Password Credentials", so it always fails when the
#     token request contains "grant_type=password".
#


require 'sinatra'
require 'rest_client'
require 'json'
require 'base64'


#--------------------------------------------------
# Authlete Base URL
#--------------------------------------------------
$AUTHLETE_BASE_URL = "https://evaludation-dot-authlete.appspot.com"


#--------------------------------------------------
# Service Credentials issued by Authlete
#--------------------------------------------------
$SERVICE_API_KEY    = "15239473208"
$SERVICE_API_SECRET = "s0PYoOtrkO90wdWSNFz-8M8T44CYaVYn8C9Adtmq8R4"


#--------------------------------------------------
# Sinatra Configuration
#--------------------------------------------------
configure do
  enable :sessions
  set :session_secret, $SERVICE_API_SECRET
end


#--------------------------------------------------
# Class representing a Web response
#--------------------------------------------------
class WebResponse
  # Constructor with an HTTP status and an entity body.
  def initialize(status, body = nil)
    # HTTP status
    @status = status

    # Entity body
    @body = body

    # HTTP headers
    @headers = {
      "Cache-Control" => "no-store",
      "Pragma"        => "no-cache"
    }
  end

  # Set an HTTP header.
  def set_header(name, value)
    @headers[name] = value
    
    return self
  end

  # Set "application/json".
  def json
    return set_header("Content-Type", "application/json;charset=UTF-8")
  end

  # Set "text/plain".
  def plain
    return set_header("Content-Type", "text/plain;charset=UTF-8")
  end

  # Set "text/html".
  def html
    return set_header("Content-Type", "text/html;charset=UTF-8")
  end

  # Set Location header.
  def location(location)
    return set_header("Location", location)
  end

  # Set WWW-Authenticate header.
  def wwwAuthenticate(challenge)
    return set_header("WWW-Authenticate", challenge)
  end

  # Create an array containing an HTTP status, HTTP headers
  # and an entity body, which is suitable as an object returned
  # from sinatra endpoints.
  def to_response
    return [@status, @headers, @body]
  end

  # Create a WebException containing this WebResponse.
  def to_exception
    return WebException.new(self)
  end
end


#--------------------------------------------------
# Exception having a Web response
#--------------------------------------------------
class WebException < StandardError
  # Constructor with a Web response.
  def initialize(response)
    @response = response
  end

  # Create an array containing an HTTP status, HTTP headers
  # and an entity body, which is suitable as an object returned
  # from sinatra endpoints.
  def to_response
    return @response.to_response
  end
end


#--------------------------------------------------
# Call Authlete's API.
#--------------------------------------------------
def call_api(path, parameters)
  # Build the payload.
  payload = JSON.generate(parameters)

  begin
    # Call Authlete's API.
    response = RestClient::Request.new(
      :url      => $AUTHLETE_BASE_URL + path,
      :method   => :post,
      :user     => $SERVICE_API_KEY,
      :password => $SERVICE_API_SECRET,
      :headers  => { :content_type => :json },
      :payload  => payload
    ).execute
  rescue => e
    begin
      # Use "resultMessage" if the response can be parsed as JSON.
      message = JSON.parse(e.response.to_str)["resultMessage"]
    rescue
      # Build a generic error message.
      message = "Authlete's #{path} API failed."
    end

    # The API call failed.
    raise WebResponse.new(500, message).plain.to_exception;
  end

  # The response from the API is JSON.
  return JSON.parse(response.to_str)
end


#--------------------------------------------------
# Call Authlete's /auth/authorization API.
#--------------------------------------------------
def call_authorization_api(params)
  return call_api("/api/auth/authorization", {
    "parameters" => URI.encode_www_form(params)
  })
end


#--------------------------------------------------
# Call Authlete's /auth/authorization/fail API.
#--------------------------------------------------
def call_authorization_fail_api(ticket, reason)
  return call_api("/api/auth/authorization/fail", {
    "ticket" => ticket,
    "reason" => reason
  })
end


#--------------------------------------------------
# Call Authlete's /auth/authorization/issue API.
#--------------------------------------------------
def call_authorization_issue_api(ticket, subject, authTime)
  return call_api("/api/auth/authorization/issue", {
    "ticket"   => ticket,
    "subject"  => subject,
    "authTime" => authTime
  })
end


#--------------------------------------------------
# Call Authlete's /auth/token API.
#--------------------------------------------------
def call_token_api(params, clientId, clientSecret)
  return call_api("/api/auth/token", {
    "parameters"   => URI.encode_www_form(params),
    "clientId"     => clientId,
    "clientSecret" => clientSecret
  })
end


#--------------------------------------------------
# Call Authlete's /auth/token/fail API.
#--------------------------------------------------
def call_token_fail_api(ticket, reason)
  return call_api("/api/auth/token/fail", {
    "ticket" => ticket,
    "reason" => reason
  })
end


#--------------------------------------------------
# Call Authlete's /auth/introspection API.
#--------------------------------------------------
def call_introspection_api(token, scopes, subject)
  return call_api("/api/auth/introspection", {
    "token"   => token,
    "scopes"  => scopes,
    "subject" => subject
  })
end


#--------------------------------------------------
# Call Authlete's /auth/authorization API and
# dispatch the processing according to the action.
#--------------------------------------------------
def do_authorization(params, session)
  # Call Authlete's /auth/authorization API.
  response = call_authorization_api(params)

  # The content of the response to the client.
  content = response["responseContent"]

  # "action" denotes the next action.
  case response["action"]
  when "INTERNAL_SERVER_ERROR"
    # 500 Internal Server Error
    #   The API request from this implementation was wrong
    #   or an error occurred in Authlete.
    return WebResponse.new(500, content).json.to_response

  when "BAD_REQUEST"
    # 400 Bad Request
    #   The authorization request was invalid.
    return WebResponse.new(400, content).json.to_response

  when "LOCATION"
    # 302 Found
    #   The authorization request was invalid and the error
    #   is reported to the redirect URI using Location header.
    return WebResponse.new(302).location(content).to_response

  when "FORM"
    # 200 OK
    #   The authorization request was invalid and the error
    #   is reported to the redirect URI using HTML Form Post.
    return WebResponse.new(200, content).html.to_response

  when "NO_INTERACTION"
    # Process the authorization request w/o user interaction.
    return handle_no_interaction(response)

  when "INTERACTION"
    # Process the authorization request with user interaction.
    return handle_interaction(session, response)

  else
    # This never happens.
    return WebResponse.new(500, "Unknown action").plain.to_response
  end
end


#--------------------------------------------------
# Call Authlete's /auth/authorization/fail API and
# dispatch the processing according to the action.
#--------------------------------------------------
def do_authorization_fail(ticket, reason)
  # Call Authlete's /auth/authorization/fail API.
  response = call_authorization_fail_api(ticket, reason)

  # The content of the response to the client.
  content = response["responseContent"]

  # "action" denotes the next action.
  case response["action"]
  when "INTERNAL_SERVER_ERROR"
    # 500 Internal Server Error
    #   The API request from this implementation was wrong
    #   or an error occurred in Authlete.
    return WebResponse.new(500, content).json.to_response

  when "BAD_REQUEST"
    # 400 Bad Request
    #   The ticket is no longer valid (deleted or expired)
    #   and the reason of the invalidity was probably due
    #   to the end-user's too-delayed response to the
    #   authorization UI.
    return WebResponse.new(400, content).json.to_response

  when "LOCATION"
    # 302 Found
    #   The authorization request was invalid and the error
    #   is reported to the redirect URI using Location header.
    return WebResponse.new(302).location(content).to_response

  when "FORM"
    # 200 OK
    #   The authorization request was invalid and the error
    #   is reported to the redirect URI using HTML Form Post.
    return WebResponse.new(200, content).html.to_response

  else
    # This never happens.
    return WebResponse.new(500, "Unknown action").plain.to_response
  end
end


#--------------------------------------------------
# Call Authlete's /auth/authorization/issue API and
# dispatch the processing according to the action.
#--------------------------------------------------
def do_authorization_issue(ticket, subject, authTime)
  # Call Authlete's /auth/authorization/issue API.
  response = call_authorization_issue_api(ticket, subject, authTime)

  # The content of the response to the client.
  content = response["responseContent"]

  # "action" denotes the next action.
  case response["action"]
  when "INTERNAL_SERVER_ERROR"
    # 500 Internal Server Error
    #   The API request from this implementation was wrong
    #   or an error occurred in Authlete.
    return WebResponse.new(500, content).json.to_response

  when "BAD_REQUEST"
    # 400 Bad Request
    #   The ticket is no longer valid (deleted or expired)
    #   and the reason of the invalidity was probably due
    #   to the end-user's too-delayed response to the
    #   authorization UI.
    return WebResponse.new(400, content).json.to_response

  when "LOCATION"
    # 302 Found
    #   Triggering redirection with either (1) an authorization
    #   code, an ID token and/or an access token (on succcess)
    #   or (2) an error code (on failure).
    return WebResponse.new(302).location(content).to_response

  when "FORM"
    # 200 OK
    #   Triggering redirection with either (1) an authorization
    #   code, an ID token and/or an access token (on succcess)
    #   or (2) an error code (on failure).
    return WebResponse.new(200, content).html.to_response

  else
    # This never happens.
    return WebResponse.new(500, "Unknown action").plain.to_response
  end
end


#--------------------------------------------------
# Call Authlete's /auth/token API and dispatch the
# processing according to the action.
#--------------------------------------------------
def do_token(params, clientId, clientSecret)
  # Call Authlete's /auth/token API.
  response = call_token_api(params, clientId, clientSecret)

  # The content of the response to the client.
  content = response["responseContent"]

  # "action" denotes the next action.
  case response["action"]
  when "INVALID_CLIENT"
    # 401 Unauthorized
    #   Client authentication failed.
    return WebResponse.new(401, content).json\
      .wwwAuthenticate("Basic realm=\"/token\"").to_response

  when "INTERNAL_SERVER_ERROR"
    # 500 Internal Server Error
    #   The API request from this implementation was wrong
    #   or an error occurred in Authlete.
    return WebResponse.new(500, content).json.to_response

  when "BAD_REQUEST"
    # 400 Bad Request
    #   The token request from the client was wrong.
    return WebResponse.new(400, content).json.to_response

  when "PASSWORD"
    # Process the token request whose flow is
    # "Resource Owner Password Credentials".
    return handle_password(response)

  when "OK"
    # 200 OK
    #   The token request from the client was valid. An access
    #   token is issued to the client application.
    return WebResponse.new(200, content).json.to_response

  else
    # This never happens.
    return WebResponse.new(500, "Unknown action").plain.to_response
  end
end


#--------------------------------------------------
# Call Authlete's /auth/token/fail API and dispatch
# the processing according to the action.
#--------------------------------------------------
def do_token_fail(ticket, reason)
  # Call Authlete's /auth/token/fail API.
  response = call_token_fail_api(ticket, reason)

  # The content of the response to the client.
  content = response["responseContent"]

  # "action" denotes the next action.
  case response["action"]
  when "INTERNAL_SERVER_ERROR"
    # 500 Internal Server Error
    #   The API request from this implementation was wrong
    #   or an error occurred in Authlete.
    return WebResponse.new(500, content).json.to_response

  when "BAD_REQUEST"
    # 400 Bad Request
    #   Authlete successfully generated an error response
    #   for the client application.
    return WebResponse.new(400, content).json.to_response

  else
    # This never happens.
    return WebResponse.new(500, "Unknown action").plain.to_response
  end
end


#--------------------------------------------------
# Call Authlete's /auth/introspection API.
# A response from the API is returned when the
# access token is valid. Otherwise, a WebException
# is raised.
#--------------------------------------------------
def do_introspection(token, scopes, subject)
  # Call Authlet's /auth/introspection API.
  response = call_introspection_api(token, scopes, subject)

  # The content of the response to the client.
  content = response["responseContent"]

  # "action" denotes the next action.
  case response["action"]
  when "INTERNAL_SERVER_ERROR"
    # 500 Internal Server Error
    #   The API request from this implementation was wrong
    #   or an error occurred in Authlete.
    raise WebResponse.new(500).wwwAuthenticate(content).to_exception

  when "BAD_REQUEST"
    # 400 Bad Request
    #   The request from the client application does not
    #   contain an access token.
    raise WebResponse.new(400).wwwAuthenticate(content).to_exception

  when "UNAUTHORIZED"
    # 401 Unauthorized
    #   The presented access token does not exist or has expired.
    raise WebResponse.new(401).wwwAuthenticate(content).to_exception

  when "FORBIDDEN"
    # 403 Forbidden
    #   The access token does not cover the required scopes
    #   or the subject associated with the access token is
    #   different.
    raise WebResponse.new(403).wwwAuthenticate(content).to_exception

  when "OK"
    # The access token is valid (= exists and has not expired).
    return response

  else
    # This never happens.
    raise WebResponse.new(500, "Unknown action").plain.to_exception
  end
end


# Extract an access token (RFC 6750)
def extract_access_token(request)
  header = request.env["HTTP_AUTHORIZATION"]

  if header != nil && /^Bearer[ ]+(.+)/i =~ header
    return Base64.decode64($1)
  end

  return request["access_token"]
end


#--------------------------------------------------
# The Authorization Endpoint
#--------------------------------------------------
get '/authorization' do
  begin
    # Call Authlete's /auth/authorization API and dispatch
    # the processing according to the action in the response.
    return do_authorization(params, session)
  rescue WebException => e
    # An error occurred.
    return e.to_response
  end
end


def handle_no_interaction(response)
  # This implementation does not support "prompt=none".
  # So, handle_no_interaction always fails.
  return do_authorization_fail(response["ticket"], "UNKNOWN")
end


def handle_interaction(session, response)
  # Put the response from the /auth/authorization API into
  # the session because it is needed later at
  # '/authorization/submit'.
  session[:res] = response

  # Render the UI.
  erb :authorization_ui, :locals => { :res => response }
end


post '/authorization/submit' do
  # Extract the authorization response from the session.
  response = session[:res]

  # Extract the ticket.
  ticket = response["ticket"]

  # Clear the session.
  session[:res] = nil

  # If the end-user authorized the client application.
  if params["authorized"] == "true"
    # Issue an authorization code to the client application.
    subject  = "joe"
    authTime = Time.now.to_i / 1000
    return do_authorization_issue(ticket, subject, authTime)
  else
    # Notify the client application that the end-user denied
    # the authorization request.
    return do_authorization_fail(ticket, "DENIED")
  end
end


#--------------------------------------------------
# The Token Endpoint
#--------------------------------------------------
post '/token' do
  # Basic Authentication.
  auth = Rack::Auth::Basic::Request.new(request.env)

  # If client credentials are presented.
  if auth.provided? && auth.basic? && auth.credentials
    clientId     = auth.credentials[0]
    clientSecret = auth.credentials[1]
  end

  begin
    # Call Authlete's /auth/token API and dispatch the
    # processing according to the action in the response.
    return do_token(params, clientId, clientSecret)
  rescue WebException => e
    # An error occurred.
    return e.to_response
  end
end


def handle_password(response)
  # This implementation does not support "Resource Owner
  # Password Credentials". So, handle_password always fails.
  return do_token_fail(response["ticket"], "UNKNOWN")
end


#--------------------------------------------------
# Protected Resource Endpoint, fortune
#--------------------------------------------------
get '/fortune' do
  # Extract an access token from the request.
  token = extract_access_token(request)

  begin
    # Introspect the access token by /auth/introspection API.
    response = do_introspection(token, ["fortune"], nil)
  rescue WebException => e
    # The access token is invalid.
    return e.to_response
  end

  # Pick up a fortune.
  fortune = [
    "You will meet your fate today. Be dressed better than usual.",
    "Someone will bring you what can change your destiny. Be on the lookout.",
    "Good news will arrive. Prepare a party."
  ].sample

  # Content as JSON.
  content = JSON.generate({"fortune" => fortune})

  return WebResponse.new(200, content).json.to_response
end


#--------------------------------------------------
# Protected Resource Endpoint, saying
#--------------------------------------------------
get '/saying' do
  # Extract an access token from the request.
  token = extract_access_token(request)

  begin
    # Introspect the access token by /auth/introspection API.
    response = do_introspection(token, ["saying"], nil)
  rescue WebException => e
    # The access token is invalid.
    return e.to_response
  end

  # Pick up a saying.
  element = [
    [ "Albert Einstein",
      "A person who never made a mistake never tried anything new." ],
    [ "John F. Kennedy",
      "My fellow Americans, ask not what your country can do for you, ask what you can do for your country." ],
    [ "Steve Jobs",
      "Stay hungry, stay foolish." ],
    [ "Walt Disney",
      "If you can dream it, you can do it." ],
    [ "Peter Drucker",
      "Whenever you see a successful business, someone once made a courageous decision." ],
    [ "Thomas A. Edison",
      "Genius is one percent inspiration and ninety-nine percent perspiration." ]
  ].sample

  # Content as JSON.
  content = JSON.generate({"person" => element[0], "saying" => element[1]})

  return WebResponse.new(200, content).json.to_response
end


#--------------------------------------------------
# Redirection Endpoint
#--------------------------------------------------
get '/callback' do
  erb :callback_ui, :locals => { :params => params }
end


#--------------------------------------------------
# Top Page
#--------------------------------------------------
get '/' do
  erb :index
end


#--------------------------------------------------
# UI Test Of The Authorization Endpoint
#--------------------------------------------------
get '/authorization_ui' do
  erb :authorization_ui, :locals => {
    :res => {
      "client" => {
        "clientName" => "Client Getting Started"
      },
      "scopes" => [
        { "name" => "fortune" },
        { "name" => "saying" }
      ]
    }
  }
end


#--------------------------------------------------
# UI Templates
#--------------------------------------------------
__END__
@@ index
<html>
  <head>
    <meta charset="utf-8">
    <title>Service Getting Started</title>
    <style type="text/css">
      .font {
        font-family: 'Source Sans Pro', 'Helvetica Neue', 'Segoe UI', 'Arial', sans-serif;
        -webkit-font-smoothing: antialiased;  /* For Chrome on Mac */
        font-weight: 200;
        font-size: 20px;
      }

      body {
        margin: 0;
        text-shadow: none;
      }

      h2 {
        margin-top: 1em;
      }

      div.page_title {
        background: #333;
        color: white;
        padding: 0.5em;
        margin: 0;
        font-size: 200%;
      }

      div.content {
        padding: 20px;
      }

      div.indent {
        margin-left: 1em
      }

      button {
        padding: 0.5em;
        margin-right: 1em;
        font-size: 20px;
      }

      table {
        border-collapse: collapse;
      }

      thead tr {
        background: #CCC;
      }
    </style>
  </head>
  <body class="font">
    <div class="page_title">Service Getting Started</div>
    <div class="content">
      <h2>Authorization Request</h2>
      <div class="indent">
        <pre>
http://localhost:4567/authorization?client_id=${CLIENT_ID}&response_type=code&scope=fortune+saying</pre>

        <div style="margin-top: 2em;">
          <form method="GET" action="/authorization" target="_blank">
            <input type="hidden" name="response_type" value="code" />
            <input type="hidden" name="scope" value="fortune saying" />

            <table cellpadding="5" border="1">
              <thead>
                <tr>
                  <th>Client ID</th>
                  <th><input type="text" name="client_id" size="20" /></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td colspan="2">
                    <button type="submit" class="font">
                      <nobr>Authorization Request</nobr>
                    </button>
                  </td>
              </tbody>
            </table>
          </form>
        </div>
      </div>
      <h2>Protected Resource Request</h2>
      <div class="indent">
        <div style="margin-top: 2em;">
          <form method="GET" action="/fortune" target="_blank">
            <table cellpadding="5" border="1">
              <thead>
                <tr><th align="left">fortune</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td align="left" bgcolor="#DDD">
                    <code>http://localhost:4567/fortune?access_token=<input type="text" name="access_token" size="50"/></code>
                  </td>
                </tr>
                <tr><td><button type="submit" class="font"><nobr>Protected Resource Request</nobr></button></td></tr>
              </tbody>
            </table>
          </form>
        </div>
        <div style="margin-top: 2em;">
          <form method="GET" action="/saying" target="_blank">
            <table cellpadding="5" border="1">
              <thead>
                <tr><th align="left">saying</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td align="left" bgcolor="#DDD">
                    <code>http://localhost:4567/saying?access_token=<input type="text" name="access_token" size="51"/></code>
                  </td>
                  </tr>
                <tr><td><button type="submit" class="font"><nobr>Protected Resource Request</nobr></button></td></tr>
              </tbody>
            </table>
          </form>
        </div>
      </div>
    </div>
  </body>
</html>

@@ authorization_ui
<html>
  <head>
    <meta charset="utf-8">
    <title>Authorization Endpoint</title>
    <style type="text/css">
      .font {
        font-family: 'Source Sans Pro', 'Helvetica Neue', 'Segoe UI', 'Arial', sans-serif;
        -webkit-font-smoothing: antialiased;  /* For Chrome on Mac */
        font-weight: 200;
        font-size: 20px;
      }

      body {
        margin: 0;
        text-shadow: none;
      }

      h2 {
        margin-top: 1em;
      }

      div.page_title {
        background: #333;
        color: white;
        padding: 0.5em;
        margin: 0;
        font-size: 200%;
      }

      div.content {
        padding: 20px;
      }

      div.indent {
        margin-left: 1em
      }

      button {
        padding: 0.5em;
        margin-right: 1em;
        font-size: 20px;
        width: 150px;
      }
    </style>
  </head>
  <body class="font">
    <div class="page_title">Authorization Endpoint</div>
    <div class="content">
      <h2>Client Application</h2>
      <div class="indent">
        <%= res["client"]["clientName"] %>
      </div>

      <h2>Requested Permissions</h2>
      <ol>
      <% if res["scopes"] != nil
           res["scopes"].each do |scope| %>
        <li><%= scope["name"] %>
      <%   end
         end %>
      </ol>

      <h2>Authorize?</h2>
      <div class="indent">
        <form method="post" action="/authorization/submit">
          <button type="submit" name="authorized" value="true" class="font"
          >Authorize</button>
          <button type="submit" name="denied" value="true" class="font"
          >Deny</button>
        </form>
      </div>
    </div>
  </body>
</html>

@@ callback_ui
<html>
  <head>
    <meta charset="utf-8">
    <title>Redirection Endpoint</title>
    <style type="text/css">
      .font {
        font-family: 'Source Sans Pro', 'Helvetica Neue', 'Segoe UI', 'Arial', sans-serif;
        -webkit-font-smoothing: antialiased;  /* For Chrome on Mac */
        font-weight: 200;
        font-size: 20px;
      }

      body {
        margin: 0;
        text-shadow: none;
      }

      h2 {
        margin-top: 1em;
      }

      div.page_title {
        background: #333;
        color: white;
        padding: 0.5em;
        margin: 0;
        font-size: 200%;
      }

      div.content {
        padding: 20px;
      }

      div.indent {
        margin-left: 1em
      }

      button {
        padding: 0.5em;
        margin-right: 1em;
        font-size: 20px;
      }

      table {
        border-collapse: collapse;
      }

      thead tr {
        background: #CCC;
      }
    </style>
  </head>
  <body class="font">
    <div class="page_title">Redirection Endpoint</div>
    <div class="content">
      <h2>Query Parameters</h2>
      <div class="indent">
        <table cellpadding="5" border="1">
          <thead>
            <tr>
              <th>Name</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
          <% if params != nil
               params.each_pair do |key, value| %>
            <tr>
              <td><%= key %></td>
              <td><%= value %></td>
            <tr>
          <%   end
             end %>
          </tbody>
        </table>
      </div>

      <% if params != nil && params["code"] != nil %>
      <h2>Token Request</h2>
      <div class="indent">
        <pre>
curl http://localhost:4567/token \
     -d client_id=${CLIENT_ID} \
     -d grant_type=authorization_code \
     -d code=<%= params["code"] %></pre>

        <div style="margin-top: 2em;">
          <form method="POST" action="/token">
            <input type="hidden" name="grant_type" value="authorization_code" />
            <input type="hidden" name="code" value="<%= params["code"] %>" />

            <table cellpadding="5" border="1">
              <thead>
                <tr>
                  <th>Client ID</th>
                  <th><input type="text" name="client_id" size="20" /></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td colspan="2">
                    <button type="submit" class="font">
                      <nobr>Token Request</nobr>
                    </button>
                  </td>
              </tbody>
            </table>
          </form>
        </div>
      </div>
      <% end %>
    </div>
  </body>
</html>
