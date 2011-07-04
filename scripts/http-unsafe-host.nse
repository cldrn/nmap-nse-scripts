description = [[
http-unsafe-host checks URLs against Google's list of suspected malware and phishing servers. 

To use this script you need to have an API key to accessGoogle's Safe Browsing Lookup services.

* To learn more about Google's Safe Browsing:
http://code.google.com/apis/safebrowsing/

* To register and get your personal API key: 
http://code.google.com/apis/safebrowsing/key_signup.html
]]

---
-- @usage
-- nmap -p80 --script http-unsafe-host <host>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-unsafe-host.nse: Host is known for distributing malware.
--
-- @args http-unsafe-host.apikey Your personal Google Safe Browsing API key. 
-- @args http-unsafe-host.url URL to check. Default: <code>http/https</code>://<code>host</code> 
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"malware", "discovery", "safe"}

require "http"
require "shortport"

portrule = shortport.http

local APIKEY = ""
local API_QRY = "https://sb-ssl.google.com/safebrowsing/api/lookup?client="..SCRIPT_NAME.."&apikey="..APIKEY.."&appver=1.5.2&pver=3.0&url="

action = function(host, port)
  local malware_found = false
  local output_lns = {}

  if not(host.targetname) then
    host.targetname = host.ip
  end
  local target = nmap.registry.args["http-unsafe-host.url"] or string.format("%s://%s", port.service, host.targetname) 

  if string.len(APIKEY) < 25 then
    return string.format("[ERROR] No API key found. Update the variable APIKEY in %s or use the argument 'http-unsafe-host.apikey'",
                         SCRIPT_NAME) 
  end
 
  stdnse.print_debug(1, "%s: Checking url %s", SCRIPT_NAME, target) 
  local req = http.get_url(API_QRY..target)
  stdnse.print_debug(2, "%s", API_QRY..target)

  --The Safe Lookup API responds with a type when site is on the lists 
  if req.body then
    if http.response_contains(req, "malware") then
      output_lns[#output_lns+1] = "Host is known for distributing malware."
      malware_found = true
    end
    if http.response_contains(req, "phishing") then
      output_lns[#output_lns+1] = "Host is known for being used in phishing attacks."
      malware_found = true
    end
  end
  
  if nmap.verbosity() >= 2 and not(malware_found) then
    output_lns[#output_lns+1] = "Host is safe to browse."
  end

  if #output_lns > 0 then
    return stdnse.strjoin("\n", output_lns)
  end
end
