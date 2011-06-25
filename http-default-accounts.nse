description = [[
http-default-accounts is a script to test default credentials in a variety of devices and web applications.
]]

---
-- @usage
-- 
-- @output
--
-- @args
--
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
-- Loads data from file and returns table of fingerprints
-- Based on http-enum's load_fingerprints() 
---
local function load_fingerprints(filename, cat)
  local i
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

    -- Make sure the elements in the probes array are strings or arrays
    for i, path in pairs(fingerprint.paths) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return false, "The 'probes' table is an array, not a table; all indexes should be numeric"
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
-- MAIN
--
---
action = function(host, port)
  local fingerprintload_status, fingerprints, requests, results
  local fingerprint_filename = nmap.registry.args["http-default-accounts.fingerprintfile"] or "http-defaul-accounts-fingerprints.lua"
  local category = nmap.registry.args["http-default-accounts.category"] or false
  local basepath = nmap.registry.args["http-default-accounts.basepath"] or "/"

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
    stdnse.print_debug(2, "Processing %s", fingerprint.name)
    for _, probe in ipairs(fingerprint.paths) do
      if (results[j]) then
        local path = basepath .. probe['path']
        if( http.page_exists(results[j], result_404, known_404, path, true) ) then
          --we found some valid credentials
          if( fingerprint.login_check(host, port, path, fingerprint.login_username, fingerprint.login_password) ) then
            stdnse.print_debug(1, "%s valid default credentials found.", fingerprint.name)
            -- Add to http credentials table
            if ( not( nmap.registry['credentials'] ) ) then
              nmap.registry['credentials'] = {}
            end
            if ( not( nmap.registry.credentials['http'] ) ) then
              nmap.registry.credentials['http'] = {}
            end
            table.insert( nmap.registry.credentials.http, { username = fingerprint.login_username, password = fingerprint.login_password } )
          end
        end
      end
      j = j + 1
    end
  end
  
end
