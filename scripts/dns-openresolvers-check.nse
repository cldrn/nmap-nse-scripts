description = [[
dns-openresolvers-check looks up the database "dnsbl.openresolvers.org" to detect DNS servers known to allow open recursion. If the DNS server is found, it will be marked as vulnerable as it can be abused via DNS amplification attacks.

This script queries a database provided by http://dns.measurement-factory.com.

Daily reports of open resolvers found:
* http://dns.measurement-factory.com/surveys/openresolvers/ASN-reports/

DNS aplification attacks:
* http://isotf.org/news/DNS-Amplification-Attacks.pdf
]]

---
-- @usage nmap -sV --script dns-openresolvers-check <target>
-- @usage nmap -sV -p53 --script dns-openresolvers-check <target>
-- 
-- @output
-- | dns-openresolvers-check: 
-- |   VULNERABLE:
-- |   This DNS server has been blacklisted as an open resolver.
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |           This DNS server is known for supporting open recursion. Open resolvers are dangerous 
-- |           because of the following reasons:
-- |           * Attackers may consume resources of third parties. They are actively being exploited in DDoS attacks.
-- |           * Attackers may poison the cache of an open resolver.
-- |       
-- |     References:
-- |       http://isotf.org/news/DNS-Amplification-Attacks.pdf
-- |_      http://dns.measurement-factory.com/surveys/openresolvers.html
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

local dns = require "dns"
local stdnse = require "stdnse"
local shortport = require "shortport"
local vulns = require "vulns"

--portrule = shortport.portnumber(53, {"tcp","udp"})

--Maybe we dont need the service running,
-- we are looking at a database afterall
hostrule = function(host) return true end 

local DNSBL = "dnsbl.openresolvers.org"

action = function(host, port)
  local server = host.ip
  local dnsbl_qry = server.."."..DNSBL
  local qry_status, qry_res = nil 
  local vuln_table = {
    title = "This DNS server has been blacklisted as an open resolver.",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
    This DNS server is known for supporting open recursion. Open resolvers are dangerous 
    because of the following reasons:
    * Attackers may consume resources of third parties. They are actively being exploited in DDoS attacks.
    * Attackers may poison the cache of an open resolver.
]],

    references = {
     'http://isotf.org/news/DNS-Amplification-Attacks.pdf',
     'http://dns.measurement-factory.com/surveys/openresolvers.html',
    }
  }
  
  stdnse.print_debug(1, "%s:Querying %s", SCRIPT_NAME, dnsbl_qry)
  qry_status, qry_res = dns.query(dnsbl_qry)
  stdnse.print_debug(1, "%s:DNS query returned:%s", SCRIPT_NAME, qry_res)

  if qry_res == "127.0.0.2" then
    stdnse.print_debug(1, "%s:DNS server is open for recursion", SCRIPT_NAME)
    vuln_table.state = vulns.STATE.VULN
    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    return report:make_output(vuln_table) 	
  end

  return nil
end
