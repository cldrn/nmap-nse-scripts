description = [[
Attempts to find Trendnet webcams vulnerable to unauthenticated access to the video stream by querying the URI "/anony/mjpg.cgi".

Original advisory: http://console-cowboys.blogspot.com/2012/01/trendnet-cameras-i-always-feel-like.html
]]

categories = {"exploit","vuln"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local uri = "/anony/mjpg.cgi"

  local _, status_404, _ = http.identify_404(host, port)
  if status_404 == 200 then
    stdnse.print_debug(1, "%s: Web server returns ambigious response. Exiting.", SCRIPT_NAME)
    return
  end

  stdnse.print_debug(1, "%s: HTTP HEAD %s", SCRIPT_NAME, uri)
  local resp = http.head(host, port, uri)
  if resp.status and http.page_exists(resp, resp_404, nil, uri) then
    return string.format("Trendnet webcam video feed:http://%s/anony/mjpg.cgi", host.ip)
  end
end
