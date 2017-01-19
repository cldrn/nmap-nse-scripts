local openssl = require "openssl"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"
local unpwdb = require "unpwdb"

description = [[
Attempts to enumerate valid email addresses using Google's Internal People API. If a valid email address is found, it 
also grabs the display name and photo from the profile.

This script uses 'unpwdb' for username guessing but you can provide your own list (--script-args userdb=/tmp/user.lst). 
A valid Google account must be provided to communicate with the API.

References:
https://developers.google.com/people/api/rest/

TODO:
* Implement OAUTH to replace username and password.
]]

---
-- @usage
-- nmap -sn --script google-people-enum --script-args='username=<username>,password=<password>' <domain>
-- @usage
-- nmap -sn --script google-people-enum --script-args='username=<username>,password=<password>,domain=<domain>' <target>
--
-- @output
-- Host script results:
-- | google-people-enum: 
-- |   users: 
-- |     
-- |       user1@example.com: 
-- |         photo: https://lh3.googleusercontent.com/XXXXXXXXXXXXX/photo.jpg
-- |         name: User 1
-- |     
-- |       user2@example.com: 
-- |_        photo: https://lh3.googleusercontent.com/XXXXXXXXXXXXXXX/photo.jpg
--
-- @xmloutput
-- <table key="users">
-- <table>
-- <table key="user1@example.com">
-- <elem key="photo">https://XXXXXX/photo.jpg</elem>
-- <elem key="name">User 1</elem>
-- </table>
-- </table>
-- <table>
-- <table key="user2@example.com">
-- <elem key="photo">https://XXXXXX/photo.jpg</elem>
-- </table>
-- </table>
-- </table>
--
-- @args google-people-enum.username Username to authenticate to Google's People API
-- @args google-people-enum.password Password to authenticate to Google's People API
-- @args google-people-enum.domain Domain name. 
---

categories = {"discovery", " external"}

author = {'Aaron Velasco <avelasco@websec.mx>','Paulino Calderon <calderon@websec.mx>'}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

hostrule = function() return true end

local ORIGIN = 'https://hangouts.google.com'


local function google_login(username, password)
  local options = {}
  options['header'] = {}
  options['header']['Content-Type'] = 'application/x-www-form-urlencoded'
  options['cookies'] = 'GAPS=1:9Gh-W5SRMzgYa850L3DJBw5vAD6uOQ:SCrej40XbCRKHuDY'

  local path = string.format("/signin/challenge/sl/password?gxf=AFoagUU7fJ86otMHTVv_nGnqUI8ZQW9V9Q%%3A1480734358179&Email=%s&Passwd=%s", username, password)
  local response = http.generic_request('accounts.google.com', '443', 'POST', path, options)
  return response
end

local function get_cookie(response)
  local cookie = ""
  local ids = {["APISID"]=34, ["HSID"]=17,["SAPISID"]=34,["SID"]=71,["SSID"]=17}
  for id,length in pairs(ids) do
    local s = string.find(response.header['set-cookie'], id)
    local e = s + string.len(id) + length + 1
    local sub = string.sub(response.header['set-cookie'], s, e)
    cookie = cookie .. sub
  end
  return(cookie)
end

local function sha1(message)
  local hash = ""
  local digest = openssl.sha1(message)

  for i=1,string.len(digest) do
    if string.byte(digest, i) > 15 then
      hash = hash .. string.format("%x", string.byte(digest, i))
    else
      hash = hash .. string.format("0%x", string.byte(digest, i))
    end
  end
  return hash
end

local function get_hash(cookie)
  local s = string.find(cookie, "SAPISID") + 8
  local e = s + 33
  local ts = os.time()
  return string.format("SAPISIDHASH %s_%s", ts, sha1(string.format("%s %s %s", ts, string.sub(cookie, s, e), ORIGIN)))
end

local function get_opts(cookie)
  local options = {}
  options['header'] = {}
  options['header']['Authorization'] = get_hash(cookie)
  options['header']['X-HTTP-Method-Override'] = 'GET'
  options['header']['Content-Type'] = 'application/x-www-form-urlencoded'
  options['header']['origin'] = ORIGIN
  options['cookies'] = cookie

  return options
end

local function lookup(email, options)
  local path = string.format("/v2/people/lookup?id=%s&type=EMAIL&matchType=EXACT&requestMask.includeField.paths=person.email"..
               "&requestMask.includeField.paths=person.gender&requestMask.includeField.paths=person.in_app_reachability"..
               "&requestMask.includeField.paths=person.metadata&requestMask.includeField.paths=person.name"..
               "&requestMask.includeField.paths=person.phone&requestMask.includeField.paths=person.photo"..
               "&requestMask.includeField.paths=person.read_only_profile_info&extensionSet.extensionNames=HANGOUTS_ADDITIONAL_DATA"..
               "&extensionSet.extensionNames=HANGOUTS_OFF_NETWORK_GAIA_LOOKUP&extensionSet.extensionNames=HANGOUTS_PHONE_DATA"..
               "&coreIdParams.useRealtimeNotificationExpandedAcls=true&key=AIzaSyAfFJCeph-euFSwtmqFZi0kaKk-cZ5wufM", email)
  local response = http.generic_request('people-pa.clients6.google.com', '443', 'POST', path, options)
  local userdata = {}
  if http.response_contains(response, email) then
    local status, person = json.parse(response.body)
    local lookupId = person['matches'][1]['lookupId']
    local personId = person['matches'][1]['personId'][1]
    local displayName
    local photo

    userdata[lookupId] = {}
    if person['people'][personId]['name'] then
      displayName = person['people'][personId]['name'][1]['displayName']
      stdnse.debug1("Display name:%s", displayName)
      userdata[lookupId].name = displayName
    end
    if person['people'][personId]['photo'] then
      photo = person['people'][personId]['photo'][1]['url']
      stdnse.debug1("Photo:%s", photo)
      userdata[lookupId].photo = photo
    end

    return true, userdata
  else
    stdnse.debug2("User '%s' wasn't found.", email)
    return false, 'No match'
  end
end

local function google_logout(cookie)
  local options = {}
  options['cookies'] = cookie
  local response = http.generic_request('accounts.google.com', '443', 'GET', '/Logout', options)
  return 
end

action = function(host, port)
  local username  = stdnse.get_script_args(SCRIPT_NAME .. ".username") or nil
  local password  = stdnse.get_script_args(SCRIPT_NAME .. ".password") or nil
  local target = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or nil
  local output = stdnse.output_table()

  if not(target) then
    if host.name then
      target = host.name
    else
      stdnse.debug1("Target not specified and Nmap couldn't resolve hostname.")
      return "[ERROR] Please set a target with the script argument google-people-enum.domain."
    end
  end

  if not(username) or not(password) then
    return "[ERROR] This script needs a valid Google username (google-people-enum.username) and password (google-people-enum.password)."
  end
 
  local response = google_login(username, password)

  if http.response_contains(response, "CheckCookie") then 
    cookie = get_cookie(response)
    options = get_opts(cookie)
    local tmp = {}
    local try = nmap.new_try()
    local usernames = try(unpwdb.usernames())
    for username in usernames do
      stdnse.debug1("Checking if user '%s@%s' exists", username, target)
      local status, result = lookup(string.format("%s@%s", username, target), options)
      if status then
        stdnse.debug1("User '%s' exists! Display name:%s Photo:%s", username, result.name, result.photo)
        table.insert(tmp, result)
      end
    end

    google_logout(cookie)
    if #tmp>0 then
      output.users = tmp
      return output
    end
  end
end
