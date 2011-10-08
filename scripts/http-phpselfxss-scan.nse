description = [[
Crawls a web server looking for PHP files vulnerable to PHP_SELF cross site scripting vulnerabilities.

This script crawls the webserver to create a list of PHP files and then sends an attack vector/probe to all of them to identify PHP_SELF cross site scripting vulnerabilities.
PHP_SELF XSS refers to cross site scripting vulnerabilities caused by the lack of sanitation of the variable <code>$_SERVER["PHP_SELF"]</code> in PHP scripts. This variable is
commonly used in php scripts with forms and a lot of developers out there think it's safe to print it without escaping it first.

Examples of Cross Site Scripting vulnerabilities in the variable $_SERVER[PHP_SELF]:
*http://www.securityfocus.com/bid/37351
*http://software-security.sans.org/blog/2011/05/02/spot-vuln-percentage

The attack vector/probe used is: <code>/'"/><script>alert(1)</script></code>
You may test this script against http://calder0n.com/sillyapp/
]]

---
-- @usage
-- nmap -p80 --script http-phpself-xss --script-args 'http-phpself-xss.path=/sillyapp/' <host/ip>
-- It's important you don't forget the last / if you're setting a path
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-phpself-xss: Possible PHPSELF XSS: http://calder0n.com/sillyapp/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
-- |_Possible PHPSELF XSS: http://calder0n.com/sillyapp/three.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

require "http"
require "shortport"
require "stdnse"
require "httpspider"

portrule = shortport.http

local DEFAULT_PATH = "/"

local OPT_PATH = stdnse.get_script_args(SCRIPT_NAME..".basepath") or DEFAULT_PATH

-- PHP_SELF Attack vector
local PHP_SELF_PROBE = '/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E'

--Launches probe request
--@param host Hostname
--@param port Port number
--@param uri URL String
--@return True if page is vulnerable/attack vector was found in body
local function launch_probe(host, port, uri)
  local probe_response

  stdnse.print_debug(1, "HTTP GET %s%s", uri, PHP_SELF_PROBE)
  probe_response = http.get(host, port, uri .. PHP_SELF_PROBE)
  if http.response_contains(probe_response, "<script>alert%(1%)</script>", false) then
	stdnse.print_debug(2, "%s: Vulnerable URI", SCRIPT_NAME, uri)
    return true
  end
  return false
end

--MAIN
action = function(host, port)
  local output = {"Vulnerable files:"}
  httpspider.crawl(host, port, OPT_PATH)
  local uris = httpspider.get_sitemap()

  for _, uri in pairs(uris) do
    local extension = httpspider.get_uri_extension(uri)
    if extension == ".php" then
      stdnse.print_debug(2, "%s: PHP file found -> %s", SCRIPT_NAME, uri)
      if launch_probe(host, port, uri) then
        output[ #output + 1 ] = string.format("%s", uri)
      end
    end
  end

  return #output > 1 and stdnse.strjoin("\n", output) or nil

end
