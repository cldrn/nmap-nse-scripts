description = [[
http-default-accounts tests for access with default credentials in a variety of web applications and devices.

This script depends on a fingerprint file containing the target's information: name, category, location paths, default credentials and login routine.
http-default-accounts searches the paths and if a page is found, it launches the corresponding login routine to check if the default login credentials are valid.

You may select a category if you wish to reduce the number of requests. We have categories like:
* <code>web</code> - Web applications
* <code>router</code> - Routers
* <code>voip</code> - VOIP devices

Please help improve this script by adding new entries to nselib/data/http-default-accounts.lua

Remember each fingerprint must have:
* <code>name</code> - Descriptive name
* <code>category</code> - Category
* <code>login_username</code> - Default username
* <code>login_password</code> - Default password
* <code>paths</code> - Paths table containing the possible location of the target
* <code>login_check</code> - Login function of the target
]]

---
-- @usage
-- nmap -p80 --script http-default-accounts host/ip
-- @output
--
-- @args http-default-accounts.basepath Base path to append to requests. Default: "/"
-- @args http-default-accounts.fingerprintfile Fingerprint filename. Default:http-default-accounts-fingerprints.lua
-- @args http-default-accounts.category Selects a category of fingerprints to use.
-- 
-- Other useful arguments relevant to this script:
-- http.pipeline Sets max number of petitions in the same request.
-- http.useragent User agent for HTTP requests
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "auth"}

require "http"
require "shortport"
portrule = shortport.http

local SCRIPT_NAME = "http-default-accounts"

---
-- load_fingerprints(filename, category)
-- Loads data from file and returns table of fingerprints if sanity checks are passed
-- Based on http-enum's load_fingerprints() 
---
local function load_fingerprints(filename, cat)
  local file, filename_full, fingerprints

  -- Check if fingerprints are cached
  if(nmap.registry.http_default_accounts_fingerprints ~= nil) then
    stdnse.print_debug(1, "%s: Loading cached fingerprints", SCRIPT_NAME)
    return nmap.registry.http_default_accounts_fingerprints
  end

  -- Try and find the file; if it isn't in Nmap's directories, take it as a direct path
  filename_full = nmap.fetchfile('nselib/data/' .. filename)
  if(not(filename_full)) then
    filename_full = filename
  end

  -- Load the file
  stdnse.print_debug(1, "%s: Loading fingerprints: %s", SCRIPT_NAME, filename_full)
  file = loadfile(filename_full)
  if( not(file) ) then
    stdnse.print_debug(1, "%s: Couldn't load the file: %s", SCRIPT_NAME, filename_full)
    return false, "Couldn't load fingerprint file: " .. filename_full
  end
  setfenv(file, setmetatable({fingerprints = {}; }, {__index = _G}))
  file()
  fingerprints = getfenv(file)["fingerprints"]

  -- Sanity check our file to ensure that all the fields were good.
  for i, fingerprint in pairs(fingerprints) do

    -- Make sure we have a valid index
    if(type(i) ~= 'number') then
      return false, "The 'fingerprints' table is an array, not a table; all indexes should be numeric"
    end
    -- Make sure they have either a string or a table of paths
    if(not(fingerprint.paths) or
      (type(fingerprint.paths) ~= 'table' and type(fingerprint.paths) ~= 'string') or
      (type(fingerprint.paths) == 'table' and #fingerprint.paths == 0)) then
      return false, "Invalid path found in fingerprint entry #" .. i
    end

    -- Make sure fingerprint.path is a table
    if(type(fingerprint.paths) == 'string') then
      fingerprint.paths = {fingerprint.paths}
    end

    -- Make sure the elements in the paths array are strings or arrays
    for i, path in pairs(fingerprint.paths) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return false, "The 'paths' table is an array, not a table; all indexes should be numeric"
      end

      -- Convert the path to a table if it's a string
      if(type(path) == 'string') then
        fingerprint.paths[i] = {path=fingerprint.paths[i]}
        path = fingerprint.paths[i]
      end

      -- Make sure the probes table has a 'path'
      if(not(path['path'])) then
        return false, "The 'paths' table requires each element to have a 'path'."
      end
    end
     -- Make sure they include the login function
    if(type(fingerprint.login_check) ~= "function") then
      return false, "Missing or invalid login_check function in entry #"..i
    end
      -- Are missing any fields?
    if(fingerprint.category and type(fingerprint.category) ~= "string") then
      return false, "Missing or invalid category in entry #"..i
    end
    if(fingerprint.name and type(fingerprint.name) ~= "string") then
      return false, "Missing or invalid name in entry #"..i
    end
    if(fingerprint.login_username and type(fingerprint.login_username) ~= "string") then
      return false, "Missing or invalid login_username in entry #"..i
    end
    if(fingerprint.login_password and type(fingerprint.login_password) ~= "string") then
      return false, "Missing or invalid login_password in entry #"..i
    end

  end

  -- Category filter
  if ( cat ) then
    local filtered_fingerprints = {}
    for _, fingerprint in pairs(fingerprints) do
      if(fingerprint.category == cat) then
        table.insert(filtered_fingerprints, fingerprint)
      end
    end
    fingerprints = filtered_fingerprints
  end

  -- Check there are fingerprints to use
  if(#fingerprints == 0 ) then
    return false, "No fingerprints were loaded after processing ".. filename
  end

  return true, fingerprints
end

---
-- format_basepath(basepath)
-- Removes trailing and leading dashes in a string
---
local function format_basepath(basepath)
  -- Remove trailing slash, if it exists
  if(#basepath > 1 and string.sub(basepath, #basepath, #basepath) == '/') then
    basepath = string.sub(basepath, 1, #basepath - 1)
  end
  -- Add a leading slash, if it doesn't exist
  if(#basepath <= 1) then
    basepath = ''
  else
    if(string.sub(basepath, 1, 1) ~= '/') then
      basepath = '/' .. basepath
    end
  end
  return basepath  
end

---
-- register_http_credentials(username, password)
-- Stores HTTP credentials in the registry. If the registry entry hasn't been
-- initiated, it will create it and store the credentials.
---
local function register_http_credentials(login_username, login_password) 
  if ( not( nmap.registry['credentials'] ) ) then
    nmap.registry['credentials'] = {}
  end
  if ( not( nmap.registry.credentials['http'] ) ) then
    nmap.registry.credentials['http'] = {}
  end
  table.insert( nmap.registry.credentials.http, { username = login_username, password = login_password } )
end

---
-- MAIN
-- Here we iterate through the paths to try to find 
-- 
---
action = function(host, port)
  local fingerprintload_status, fingerprints, requests, results
  local fingerprint_filename = nmap.registry.args["http-default-accounts.fingerprintfile"] or "http-defaul-accounts-fingerprints.lua"
  local category = nmap.registry.args["http-default-accounts.category"] or false
  local basepath = nmap.registry.args["http-default-accounts.basepath"] or "/"
  local output_lns = {}

  --Load fingerprint data or abort 
  status, fingerprints = load_fingerprints(fingerprint_filename, category)
  if(not(status)) then
    return stdnse.format_output(false, fingerprints)
  end
  stdnse.print_debug(1, "%s: %d fingerprints were loaded", SCRIPT_NAME, #fingerprints)

  --Format basepath: Removes or adds slashs
  basepath = format_basepath(basepath)
 
  requests = {}

  -- Add requests to http pipeline
  stdnse.print_debug(1, "%s: Searching for entries under path '%s' (change with '%s.basepath' argument)", SCRIPT_NAME, basepath, SCRIPT_NAME)
  for i = 1, #fingerprints, 1 do
    for j = 1, #fingerprints[i].paths, 1 do
      requests = http.pipeline_add(basepath .. fingerprints[i].paths[j].path, nil, requests, 'GET')
    end
  end

  -- Perform all the requests 
  results = http.pipeline_go(host, port, requests, nil)
  if results == nil then
    return "[ERROR] HTTP request table is empty. This should not happen since we at least made one request."
  end

  -- Record 404 response
  local result, result_404, known_404 = http.identify_404(host, port)
  if(result == false) then
    return stdnse.format_output(false, result_404)
  end

  -- Iterate through responses to find a match
  local j = 1
  for i, fingerprint in ipairs(fingerprints) do
    stdnse.print_debug(1, "%s: Processing %s", SCRIPT_NAME, fingerprint.name)
    for _, probe in ipairs(fingerprint.paths) do

      if (results[j]) then
        local path = basepath .. probe['path']

        if( http.page_exists(results[j], result_404, known_404, path, true) ) then

          --we found some valid credentials
          if( fingerprint.login_check(host, port, path, fingerprint.login_username, fingerprint.login_password) ) then
            stdnse.print_debug(1, "%s valid default credentials found.", fingerprint.name)
            output_lns[#output_lns + 1] = string.format("[%s] credentials found -> %s:%s Path:%s", 
                                          fingerprint.name, fingerprint.login_username, fingerprint.login_password, path)
            -- Add to http credentials table
            register_http_credentials(fingerprint.login_username, fingerprint.login_password)
         end

        end
      end
      j = j + 1
    end
  end
  if #output_lns > 0 then
    return stdnse.strjoin("\n", output_lns)
  end
end
