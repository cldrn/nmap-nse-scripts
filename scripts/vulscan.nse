description = [[
Attempts to discover vulnerabilities by matching information from the 
version detection engine with databases such as CVE, ExploitDB and 
Scipvuldb. 

This script uses version information (-sV) to match product names with 
vulnerability databases stored in Nmap's NSE data directory. The 
databases are distributed separately, hence they need to be download 
 manually before using the script. Optionally you may create empty 
placeholder files and execute the script update functionality to populate
 the databases (--script-args updatedb).

The following databases are supported at the moment (in nselib/data/):

* Scipvuldb (http://www.scip.ch/en/?vuldb)
  Vulnerability feed URL: http://www.scip.ch/vuldb/scipvuldb.csv
* CVE (http://cve.mitre.org)
  Vulnerability feed URL: http://cve.mitre.org/data/downloads/allitems.csv
* ExploitDB (http://www.exploit-db.com)
  Vulnerability feed URL: 
  https://raw.githubusercontent.com/offensive-security/exploit-database/master/files.csv

It is also possible to create and reference your own databases. This
requires to create a database file with the following structure:

  <id>;<title>

Just execute vulscan like you would by refering to one of the pre-
delivered databases. Feel free to share your own database and
vulnerability connection with me, to add it to the official
repository.

Vulnerability detection of this script is only as good as Nmap version detection
and the vulnerability database entries are. Some databases do not
provide conclusive version information, which may lead to a lot of
false-positives.

REPORTING

It is possible to use another pre-defined report structure with the
script argument vulscanoutput. The supported output formats are:
* details
* listid
* listlink
* listtitle

You may enforce your own report structure by using a format string 
 as follows:
* --script-args vulscanoutput='{link}\n{title}\n\n'
* --script-args vulscanoutput='ID: {id} - Title: {title} ({matches})\n'
* --script-args vulscanoutput='{id} | {product} | {version}\n'

The supported elements in a dynamic report template are:

* {id}      ID of the vulnerability
* {title}   Title of the vulnerability
* {matches} Count of matches
* {product} Matched product string(s)
* {version} Matched version string(s)
* {link}    Link to the vulnerability database entry
* \n        Newline
* \t        Tab

Every default database comes with an url and a link, which is used
during the scanning and might be accessed as {link} within the
customized report template. To use custom database links, use the
script argument 'vulscandblink':
* --script-args "vulscandblink=http://example.org/{id}"

Special credits go to Marc Ruef for creating the original vulscan script
 and maintaning the vulnerability database Scipvuldb.
]]

---
-- @args vulscan.updatedb Updates the supported vulnerability databases.
-- @args vulscan.db Sets the vulnerability database to use in a scan.
-- @args vulscan.versiondetection Enables/disables version detection matching.
-- @args vulscan.showall Show all possible matches (Prone to false positives).
-- @args vulscan.interactive Enables interactive mode which allows users to manually 
--       override version strings.
-- @args vulscan.output Sets the report's output format. 
-- 
-- @usage nmap --script vulscan --script-args vulscan.updatedb=1 <target>
-- @usage nmap --script vulscan --script-args vulscan.db=<vulnerability_database> <target>
-- @usage nmap --script vulscan --script-args vulscan.db=cve.csv <target>
-- @usage nmap --script vulscan --script-args vulscan.versiondetection=0 <target>
-- @usage nmap --script vulscan --script-args vulscan.showall=1 <target>
-- @usage nmap --script vulscan --script-args vulscan.interactive=1 <target>
-- @usage nmap --script vulscan --script-args vulscan.output=listid <target>
-- @usage nmap --script vulscan --script-args vulscan.output='{link}\n{title}\n\n' <target>
-- @usage nmap --script vulscan --script-args vulscan.dblink="http://example.org/{id}" <target>
--
-- @output
-- PORT   STATE SERVICE REASON  VERSION
-- 25/tcp open  smtp    syn-ack Exim smtpd 4.69
-- | osvdb (22 findings):
-- | [2440] qmailadmin autorespond Multiple Variable Remote Overflow
-- | [3538] qmail Long SMTP Session DoS
-- | [5850] qmail RCPT TO Command Remote Overflow DoS
-- | [14176] MasqMail Piped Aliases Privilege Escalation
---

author = {"Marc Ruef <marc.ruef-at-computec.ch>", "Jiayi Ye", "Paulino Calderon"}
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

local stdnse = require "stdnse"
local http = require "http"

local DATA_PATH = "nselib/data/"

portrule = function(host, port)
  if port.version.product ~= nil and port.version.product ~= "" then
    return true
  else
    stdnse.debug1("No version detection data available. Analysis not possible.")
  end
end

-- check if database exists before starting
local function check_vuln_db(db)
  local filepath = nmap.fetchfile(DATA_PATH .. db)
  if filepath then
    return true
  end
  return false
end

--Writes string to file
--Taken from: hostmap.nse
-- @param filename Filename to write
-- @param contents Content of file
-- @return True if file was written successfully
local function write_file (filename, contents)
  local filepath = nmap.fetchfile(DATA_PATH.. filename)
  local f, err = io.open(filepath, "w");
  if not f then
    return f, err;
  end
  f:write(contents);
  f:close();
  return true;
end

local function update_cve(url, filename)
  -- Replace spaces in the path with %20
  url = string.gsub(url, " ", "%%20")

  local result = http.get_url(url)
  if(result['status'] ~= 200 or result['content-length'] == 0) then
    return false
  end
  local content = ""
  local regexp = "(CVE[^,]+),[^,]+,\"([^\"]+)\","
  for line in string.gmatch(result.body,"[^\n]+") do
    local id, name = string.match(line, regexp)
    if id and name then
      content = content .. id .. ";" .. name .. "\n"
    end
  end
  return write_file(filename, content)
end

local function update_exploit_db(url, filename)
  -- Replace spaces in the path with %20
  url = string.gsub(url, " ", "%%20")

  local result = http.get_url(url)
  if(result['status'] ~= 200 or result['content-length'] == 0) then
    return false
  end
  local content = ""
  local regexp = "([^,]+),[^,]+,\"([^\"]+)\","
  for line in string.gmatch(result.body,"[^\n]+") do
    local id, name = string.match(line, regexp)
    if id and name then
      content = content .. id .. ";" .. name .. "\n"
    end
  end
  return write_file(filename, content)
end

local function update_scip_db(url, filename)
  -- Replace spaces in the path with %20
  url = string.gsub(url, " ", "%%20")

  local result = http.get_url(url)
  if(result['status'] ~= 200 or result['content-length'] == 0) then
    return false
  end
  return write_file(filename, result.body)
end

-- update vulnerability database
local function update_vuln_db()
  local status = update_cve("http://cve.mitre.org/data/downloads/allitems.csv"
    , "cve.csv")
  if not status then
    stdnse.print_verbose("Failed to update MITRE CVE.")
  end
  status = update_exploit_db("https://raw.githubusercontent.com/" .. 
    "offensive-security/exploit-database/master/files.csv", "exploitdb.csv")
  if not status then
    stdnse.print_verbose("Failed to update Exploit-Db.")
  end
  status = update_scip_db("http://www.scip.ch/vuldb/scipvuldb.csv", 
    "scipvuldb.csv")
  if not status then
    stdnse.print_verbose("Failed to update scip VulDB.")
  end
  stdnse.debug1("Update finished")
end

-- We don't like unescaped things
local function escape(s)
  s = string.gsub(s, "%%", "%%%%")
  return s
end

-- Parse the report output structure
local function report_parsing(v, struct, link)
  local s = struct

  --database data (needs to be first)
  s = string.gsub(s, "{link}", escape(link))

  --layout elements (needs to be second)
  s = string.gsub(s, "\\n", "\n")
  s = string.gsub(s, "\\t", "\t")

  --vulnerability data (needs to be third)
  s = string.gsub(s, "{id}", escape(v.id))
  s = string.gsub(s, "{title}", escape(v.title))
  s = string.gsub(s, "{matches}", escape(v.matches))
  s = string.gsub(s, "{product}", escape(v.product))  
  s = string.gsub(s, "{version}", escape(v.version))

  return s
end

-- Get the row of a CSV file
local function extract_from_table(line, col, del)
  local val = stdnse.strsplit(del, line)

  if type(val[col]) == "string" then
    return val[col]
  end
end

-- Read a file
local function read_from_file(file)
  local filepath = nmap.fetchfile(file)

  if filepath then
    local f, err, _ = io.open(filepath, "r")
    if not f then
      stdnse.debug1("vulscan: Failed to open file %s", file)
    end

    local line, ret = nil, {}
    while true do
      line = f:read()
      if not line then break end
      ret[#ret+1] = line
    end

    f:close()

    return ret
  else
    stdnse.debug1("vulscan: File %s not found", file)
    return nil
  end
end

-- Find the product matches in the vulnerability databases
local function find_vulnerabilities(prod, ver, db, version_detection)
  local v = {}      -- matching vulnerabilities
  local v_id        -- id of vulnerability
  local v_title      -- title of vulnerability
  local v_title_lower    -- title of vulnerability in lowercase for speedup
  local v_found      -- if a match could be found

  -- Load database
  local v_entries = read_from_file(DATA_PATH .. db)
  if not(v_entries) then
    return v
  end
  local prod_words = stdnse.strsplit(" ", prod)

  stdnse.debug1("vulscan: Starting search of %s in %s (%d entries) ...", 
    prod, db, #v_entries)

  -- Iterate through the vulnerabilities in the database
  for i=1, #v_entries, 1 do
    v_id    = extract_from_table(v_entries[i], 1, ";")
    v_title    = extract_from_table(v_entries[i], 2, ";")

    if type(v_title) == "string" then
      v_title_lower = string.lower(v_title)

      local isMatch = true
      for j=1, #prod_words, 1 do
        v_found = string.find(v_title_lower, 
          escape(string.lower(prod_words[j])), 1)
        if v_found == nil then
          isMatch = false 
        end     
      end      

      if isMatch == true then
        if #v == 0 then
          -- Initiate table
          v[1] = {
            id    = v_id,
            title  = v_title,
            product  = prod,
            version  = "",
            matches  = 1
          }
        elseif v[#v].id ~= v_id then
          -- Create new entry
          v[#v+1] = {
            id    = v_id,
            title  = v_title,
            product  = prod,
            version  = "",
            matches  = 1
          }
        else
          -- Add to current entry
          v[#v].product = v[#v].product .. " " .. prod
          v[#v].matches = v[#v].matches+1
        end

        stdnse.debug2("vulscan: Match v_id %s -> v[%d] (%d match) (Prod: %s)",
          v_id, #v, v[#v].matches, prod)        
      end

      -- Additional version matching
      if version_detection ~= "0" 
        and ver ~= nil and ver ~= "" then
        --stdnse.debug1("Aditional version matching is set.")
        if v[#v] ~= nil and v[#v].id == v_id then
          for k=0, string.len(ver)-1, 1 do
            v_version = string.sub(ver, 1, string.len(ver)-k)
            v_found = string.find(string.lower(v_title), 
              string.lower(" " .. v_version), 1)

            if type(v_found) == "number" then
              v[#v].version = v[#v].version .. v_version .. " "
              v[#v].matches = v[#v].matches+1

            stdnse.debug2("vulscan: Match v_id %s -> v[%d] (%d match) (Version: %s)",
              v_id, #v, v[#v].matches, v_version)
            end
          end
        end
      end
    end
  end

  return v
end

-- Prepare the resulting matches
local function prepare_result(v, struct, link, show_all)
  local grace = 0        -- grace trigger
  local match_max = 0      -- counter for maximum matches
  local match_max_title = ""  -- title of the maximum match
  local s = ""        -- the output string

  -- Search the entries with the best matches
  if #v > 0 then
    -- Find maximum matches
    for i=1, #v, 1 do
      if v[i].matches > match_max then
        match_max = v[i].matches
        match_max_title = v[i].title
      end
    end

    stdnse.debug2("vulscan: Maximum matches of a finding are %d (%s)",
      match_max, match_max_title)

    if match_max > 0 then
      for matchpoints=match_max, 1, -1 do
        for i=1, #v, 1 do
          if v[i].matches == matchpoints then
            stdnse.debug2("vulscan: Setting up result id %d", i)
            s = s .. report_parsing(v[i], struct, link)
          end
        end

        if show_all ~= "1" and s ~= "" then
          -- If the next iteration shall be approached (increases matches)
          if grace == 0 then
            stdnse.debug2("vulscan: Best matches found in 1st pass." ..  
              "Going to use 2nd pass ...")
            grace = grace+1
          elseif show_all ~= "1" then
            break
          end
        end
      end
    end
  end

  return s
end

action = function(host, port)
  local interactive_arg = stdnse.get_script_args(SCRIPT_NAME..".interactive") or nil
  local output_arg = stdnse.get_script_args(SCRIPT_NAME..".output") or nil
  local updatedb_arg = stdnse.get_script_args(SCRIPT_NAME..".updatedb") or nil
  local dblink_arg = stdnse.get_script_args(SCRIPT_NAME..".dblink") or nil
  local db_arg = stdnse.get_script_args(SCRIPT_NAME..".db") or nil
  local showall_arg = stdnse.get_script_args(SCRIPT_NAME..".showall") or nil
  local versiondetection_arg = stdnse.get_script_args(SCRIPT_NAME..".versiondetection") or 1
 
  local mutex = nmap.mutex("vulscan")
  mutex "lock"
  if updatedb_arg then
    stdnse.debug1("Updating databases...")
    update_vuln_db()
    return string.format("Vulnerability databases updated.")
  end
  mutex "done"


  local prod = port.version.product  -- product name
  local ver = port.version.version  -- product version
  local struct = "[{id}] {title}\nURL:{link}\n"  -- default report structure
  local db = {}            -- vulnerability database
  local db_link = ""          -- custom link for vulnerability databases
  local vul = {}            -- details for the vulnerability
  local v_count = 0          -- counter for the vulnerabilities
  local s = ""            -- the output string

  stdnse.debug1("vulscan: Found service %s", prod)

  -- Go into interactive mode
  if interactive_arg then
    stdnse.debug1("vulscan: Enabling interactive mode ...")
    stdnse.print_verbose(string.format("The scan has determined the following product:%s", prod))
    stdnse.print_verbose("Press Enter to accept or define a new product name string.")
    local prod_override = io.stdin:read'*l'

    if string.len(prod_override) ~= 0 then
      prod = prod_override
      stdnse.print_verbose("New product name string: %s", prod)
    end
  end

  -- Read custom report structure
  if output_arg ~= nil then
    if output_arg == "details" then
      struct = "[{id}] {title}\nMatches: {matches}," ..  
      "Prod: {product}, Ver: {version}\n{link}\n\n"
    elseif output_arg == "listid" then
      struct = "{id}\n"
    elseif output_arg == "listlink" then
      struct = "{link}\n"
    elseif output_arg == "listtitle" then
      struct = "{title}\n"
    else
      struct = output_arg
    end
    stdnse.debug1("vulscan: Custom output structure defined as %s", struct)
  end

  -- Read custom database link
  if dblink_arg ~= nil then
    db_link = dblink_arg
    stdnse.debug1("vulscan: Custom database link defined as %s", db_link)
  end

  if db_arg then
    stdnse.debug1("vulscan: Using single mode db:%s", db_arg)
    local dbstatus = check_vuln_db(db_arg)
    if dbstatus == false then
      stdnse.print_verbose("Operation failed. Could not read database '%s'", db_arg)
      return string.format("Could not find database '%s' in your nselib/data directory.", db_arg)
    end
    vul = find_vulnerabilities(prod, ver, db_arg, versiondetection_arg)
    if #vul > 0 then
      s = s .. db_arg
      if db_link ~= "" then s = s .. " - " .. db_link end
      s = s .. ":\n" .. prepare_result(vul, struct, db_link, showall_arg) .. "\n\n"
    end
  else
    -- Add your own database, if you want to include it in the multi db mode
    db[1] = {name="MITRE CVE", file="cve.csv", 
            url="http://cve.mitre.org", 
            link="http://cve.mitre.org/cgi-bin/cvename.cgi?name={id}"}
    db[2] = {name="Exploit-DB", file="exploitdb.csv", 
            url="http://www.exploit-db.com", 
            link="http://www.exploit-db.com/exploits/{id}"}
    db[3] = {name="scip VulDB", file="scipvuldb.csv", 
            url="http://www.scip.ch/en/?vuldb", 
            link="http://www.scip.ch/en/?vuldb.{id}"}

    stdnse.debug1("vulscan: Using multi db mode (%d databases) ...", #db)
    local gstatus = false
    local dbstatus = {}
    for i, v in ipairs(db) do
      dbstatus[i] = check_vuln_db(v.file)
      gstatus = dbstatus[i] or gstatus
    end

    --if gstatus == false then
    --  mutex "lock"
    --  nmap.registry.vulscan.nodb = true
    --  mutex "done"
    --  stdnse.print_verbose("Failed: No database available.")
    --end

    for i,v in ipairs(db) do
      vul = find_vulnerabilities(prod, ver, v.file)

      s = s .. v.name .. " - " .. v.url .. ":\n"
      if vul and #vul > 0 then
        v_count = v_count + #vul
        s = s .. prepare_result(vul, struct, v.link) .. "\n"
      elseif dbstatus[i] == false then
        s = s .. "This database is not installed on the system.\n\n"
      else
        s = s .. "There were no matches. =(\n\n"
      end
      stdnse.debug1("vulscan: %d matches in %s", #vul, v.file)
    end
    stdnse.debug1("vulscan: %d matches in total", v_count)
  end

  if s then
    return s
  end
end
