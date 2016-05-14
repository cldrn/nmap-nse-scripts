description = [[
Attempts to find Trendnet TVIP110W webcams vulnerable to unauthenticated access to the video stream by querying the URI "/anony/mjpg.cgi".

Original advisory: http://console-cowboys.blogspot.com/2012/01/trendnet-cameras-i-always-feel-like.html
]]

---
-- @usage nmap -p80 --script http-trendnet-tvip110w.nse <target>
-- 
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- |_http-trendnet-webcams: Trendnet TV-IP110W video feed is unprotected:http://<target>/anony/mjpg.cgi
---


categories = {"exploit","vuln"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local uri = "/anony/mjpg.cgi"

  local _, status_404, resp_404 = http.identify_404(host, port)
  if status_404 == 200 then
    stdnse.print_debug(1, "%s: Web server returns ambigious response. Trendnet webcams return standard 404 status responses. Exiting.", SCRIPT_NAME)
    return
  end

  stdnse.print_debug(1, "%s: HTTP HEAD %s", SCRIPT_NAME, uri)
  local resp = http.head(host, port, uri)
  if resp.status and http.page_exists(resp, resp_404, nil, uri) and resp.status == 200 then
    return string.format("Trendnet TV-IP110W video feed is unprotected:http://%s/anony/mjpg.cgi", host.ip)
  end
end
