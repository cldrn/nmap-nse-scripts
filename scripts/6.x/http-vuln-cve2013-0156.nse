description = [[
Detects Ruby on Rails servers vulnerable to object injection, remote command executions and denial of service attacks. (CVE-2013-0156)

All Ruby on Rails versions before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 are vulnerable. This script 
sends a harmless malformed yaml payload as a probe to detect vulnerable installations. 

References:
* https://community.rapid7.com/community/metasploit/blog/2013/01/10/exploiting-ruby-on-rails-with-metasploit-cve-2013-0156',
* https://groups.google.com/forum/?fromgroups=#!msg/rubyonrails-security/61bkgvnSGTQ/nehwjA8tQ8EJ',
* http://cvedetails.com/cve/2013-0156/

TODO:
* Add argument to exploit cmd exec vuln 
]]

---
-- @usage
-- nmap -sV --script http-vuln-cve2013-0156 <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
--
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

portrule = shortport.http

local PAYLOAD_OK = [=[<?xml version="1.0" encoding="UTF-8"?>
<probe type="string"><![CDATA[
nmap
]]></probe>]=]

local PAYLOAD_TIME = [=[<?xml version="1.0" encoding="UTF-8"?>
<probe type="yaml"><![CDATA[
--- !ruby/object:Time {}

]]></probe>]=]

local PAYLOAD_MALFORMED = [=[<?xml version="1.0" encoding="UTF-8"?>
<probe type="yaml"><![CDATA[
--- !ruby/object:^@
]]></probe>
]=]

local function detect(host, port, uri)
  local opts = {
    header = {
      Host = host.ip,
      ["User-Agent"]  = stdnse.get_script_args("http.useragent") or "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
      ["Content-Type"] = "application/xml",
    }}
  opts["content"] = PAYLOAD_OK
  local req_ok = http.generic_request(host, port, "POST", uri, opts)
  opts["content"] = PAYLOAD_TIME
  local req_time = http.generic_request(host, port, "POST", uri, opts)
  stdnse.print_debug(1, "%s:First request returned status %d. Second request returned status %d", SCRIPT_NAME, req_ok.status, req_time.status)
  if req_ok.status == 200 and req_time.status == 200 then

    opts["content"] = PAYLOAD_MALFORMED
    local opts2 = {header={}}
    opts2["header"]["Content-type"] = 'application/xml'
    local req_malformed = http.post(host, port, uri, opts2, nil, PAYLOAD_MALFORMED)
    stdnse.print_debug(1, "%s:Malformed request returned status %d", SCRIPT_NAME, req_malformed.status)
    if req_malformed.status == 500 then
      return true
    end
  end

  return false
end

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local vuln_table = {
    title = "Parameter parsing vulnerabilities in several versions of Ruby on Rails allow object injection, remote command execution and Denial Of Service attacks (CVE-2013-0156)",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
All Ruby on Rails versions before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 are vulnerable to object injection, remote command execution and denial of service attacks. 
The attackers don't need to be authenticated to exploit these vulnerabilities.
]],

    references = {
      'https://community.rapid7.com/community/metasploit/blog/2013/01/10/exploiting-ruby-on-rails-with-metasploit-cve-2013-0156',
      'https://groups.google.com/forum/?fromgroups=#!msg/rubyonrails-security/61bkgvnSGTQ/nehwjA8tQ8EJ',
      'http://cvedetails.com/cve/2013-0156/',
    }
  }

  if detect(host,port,uri) then
    stdnse.print_debug(1, "%s:Received status 500 as expected in vulnerable installations. Marking as vulnerable...", SCRIPT_NAME)
    vuln_table.state = vulns.STATE.VULN
    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    return report:make_output(vuln_table) 
  end

  return nil
end
