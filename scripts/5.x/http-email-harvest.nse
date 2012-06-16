description = [[
http-email-harvest returns a list of email accounts found in the body text of all URIs found in the web server.
]]

---
--@usage
--nmap -sV --script http-email-harvest <target>
--nmap -sV --script http-email-harvest --script-args http.useragent=Mozilla,httpspider.ignoreParams <target>
--
--@output
--@args http-email-harvest.basepath URI base path. Default: /
--@args http-email-harvest.localOnly Shows only email accounts belonging to the scanned host. Default: false
--
--Other useful args:
--http.useragent - User Agent used in HTTP requests
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require "http"
require "shortport"
require "httpspider"

portrule = shortport.http

--Returns table of emails found in the given text
--@param text Haystack
local function find_emails(text)
  local emails = {}
  for email in string.gfind(text, '[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?') do
    table.insert(emails, email)
  end
  return emails
end

--Main
--Iterates through sitemap to find email accounts
action = function(host, port)
  local basepath = stdnse.get_script_args(SCRIPT_NAME..".basepath") or "/"
  local emails_found = {}
  local valid_emails = {}
  httpspider.crawl(host, port, basepath)
  local uris = httpspider.get_sitemap()

  for _, uri in pairs(uris) do
	  local page = http.get(host, port, uri)
	  local emails = find_emails(page.body)
	  for _, email in pairs(emails) do
      if emails_found[email] == nil then
        emails_found[email] = true
        valid_emails[#valid_emails+1] = email 
      end
	  end
  end

  return #valid_emails > 1 and stdnse.strjoin("\n", valid_emails) or nil
end
