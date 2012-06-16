description = [[
Returns a list of all web pages and files found in the web server.
]]

---
-- @usage
-- nmap -p80 --script http-sitemap --script-args http.useragent=Mozilla,httpspider.ignoreParams <host>
-- @output
--PORT   STATE SERVICE REASON
--80/tcp open  http
--| http-sitemap: URIs found:
--|_http://scanme.nmap.org/
--
-- @args http-sitemap.basepath URI base path
--
-- Other useful args:
-- http.useragent - User Agent for the HTTP requests
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require "http"
require "shortport"
require "httpspider"

portrule = shortport.http

action = function(host, port)
  local results = {"URIs found:"}
  local basepath = stdnse.get_script_args(SCRIPT_NAME..".basepath") or "/"

  httpspider.crawl(host, port, basepath)

  local uris = httpspider.get_sitemap()
  for _, uri in pairs(uris) do
    results[#results+1] = uri
  end

  return #results > 1 and stdnse.strjoin("\n", results) or nil
end
