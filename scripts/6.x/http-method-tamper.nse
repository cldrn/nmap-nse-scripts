description = [[
Crawls a web server looking for password protected resources (HTTP status 401) and attempts to bypass the authentication and access them using HTTP verb tampering.

The script determines if the protected URI is vulnerable by performing HTTP verb tampering and monitoring the status codes. First, it uses a HEAD request and then a random generated string ( This is useful as some web servers treat unknown request methods as GET ).

References:
* http://www.imperva.com/resources/glossary/http_verb_tampering.html
* https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
* http://www.mkit.com.ar/labs/htexploit/
* http://capec.mitre.org/data/definitions/274.html
]]

---
-- @usage
-- nmap --script=http-method-tamper --script-args 'http-method-tamper.paths={/path1/,/path2/}' <target>
--
-- @args http-method-tamper.paths Array of paths to check. If not set, the script will crawl the web server.
---

author = "Paulino Calderon <calderon()websec.mx>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "auth", "vuln"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local httpspider = require "httpspider"
local vulns = require "vulns"
local url = require "url"

portrule = shortport.http

--
-- Checks if the web server does not return status 401 when requesting with other HTTP verbs.
-- First, it tries with HEAD and then with a random string.
--
local function probe_http_verbs(host, port, uri)
  stdnse.print_debug(2, "%s:Tampering HTTP verbs %s", SCRIPT_NAME, uri)
  local head_req = http.head(host, port, uri)
  if head_req and head_req.status ~= 401 then
    return true
  end 
  local random_verb_req = http.generic_request(host, port, stdnse.generate_random_string(4), uri)
  if random_verb_req and random_verb_req.status ~= 401 then
    return true
  end 
  
  return false
end

action = function(host, port)
  local paths = stdnse.get_script_args(SCRIPT_NAME..".paths")
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 10000
  local vuln = {
       title = 'Authentication bypass by HTTP verb tampering',
       state = vulns.STATE.NOT_VULN,
       description = [[
Some password protected resources are vulnerable to authentication bypass by HTTP verb tampering. This web server returns different status code responses when using an unexpected HTTP verb.
       ]],
       references = {
            'http://www.imperva.com/resources/glossary/http_verb_tampering.html',
            'https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29',
            'http://capec.mitre.org/data/definitions/274.html'
       }
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local _, http_status, _ = http.identify_404(host,port)
  if ( http_status == 200 ) then
    stdnse.print_debug(1, "%s: Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", SCRIPT_NAME, host.ip, port.number)
    return false
  end
    
  -- If paths is not set, crawl the web server looking for http 401 status
  if not(paths) then
    local crawler = httpspider.Crawler:new(host, port, uri, { scriptname = SCRIPT_NAME } )
    crawler:set_timeout(timeout)

   while(true) do
      local status, r = crawler:crawl()
        if ( not(status) ) then
          if ( r.err ) then
            return stdnse.format_output(true, "ERROR: %s", r.reason)
           else
            break
          end
        end
      if r.response.status == 401 then
        stdnse.print_debug(2, "%s:%s is protected! Let's try some verb tampering...", SCRIPT_NAME, tostring(r.url))
        local parsed = url.parse(tostring(r.url))
        if probe_http_verbs(host, port, uri) then
          vuln.state = vulns.STATE.VULNERABLE
        end
      end
    end
  else 
  -- Paths were set, check them and exit. No crawling here.

    -- convert single string entry to table
    if ( "string" == type(paths) ) then
      paths = { paths }
    end
	
    for _, path in ipairs(paths) do
      local getstatus = http.get(host, port, path).status

      if getstatus == 401 then
         if probe_http_verbs(host, port, path) then
          vuln.state = vulns.STATE.VULNERABLE 
         end
      end
    
    end
  end
  return vuln_report:make_output(vuln)
end
