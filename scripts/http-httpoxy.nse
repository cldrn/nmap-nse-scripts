local stdnse = require "stdnse"
local http = require "http"
local os = require "os"
local shortport = require "shortport"
local vulns = require "vulns"

description=[[
Attempts to detect web applications vulnerable to "httpoxy" (CVE-2016-5385, CVE-2016-5386,
CVE-2016-5387, CVE-2016-5388, CVE-2016-1000109, CVE-2016-1000110).

The script attempts to detect this vulnerability by measuring the response time when 
assigning a non-existing proxy to the headers. In theory, vulnerable applications will try 
to connect to the bad proxy increasing the response time. To reduce false positives we run 
the test several times and we expect the response time from the request with the bad 
proxy to always be greater than normal responses.  

References:
* https://httpoxy.org
]]

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
author = "Paulino Calderon <calderon()websec.mx>"
categories = {"vuln","exploit"}

portrule = shortport.http

---
-- @usage
-- nmap -p80 --script http-httpoxy --script-args iterations=5 <target>
-- nmap -sV --script http-httpoxy <target>
--
-- @args http-httpoxy.path Path. Default: /
-- @args http-httpoxy.iterations Number of requests to measure response time. Default: 10 
-- @args http-httpoxy.tests Number of comparison test to run. Default: 3
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack ttl 64
-- | http-httpoxy: 
-- |   VULNERABLE:
-- |   HTTPoxy
-- |     State: VULNERABLE
-- |       This web application might be affected by the vulnerability known as HTTPoxy. It seems the 
-- |       application is reading an arbitrary proxy value from the request headers.
-- |           
-- |     Disclosure date: 2016-07-18
-- |     Extra information:
-- |       Avg response:0.003057 Avg response with bad proxy:0.008315
-- |     References:
-- |_      https://httpoxy.org
--
-- @xmloutput
-- <elem key="title">HTTPoxy</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="description">
-- <elem>This web application might be affected by the vulnerability known as HTTPoxy. It seems the 
-- &#xa;application is reading an arbitrary proxy value from the request headers.&#xa;    </elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="month">07</elem>
-- <elem key="day">18</elem>
-- <elem key="year">2016</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2016-07-18</elem>
-- <table key="extra_info">
-- <elem>Avg response:0.003918 Avg response with bad proxy:0.008839</elem>
-- </table>
-- <table key="refs">
-- <elem>https://httpoxy.org</elem>
-- </table>
---

local function get_avg(host, port, path, iterations, bad_proxy)
  local total_time = 0
  local opts = {header={}}
  opts["bypass_cache"] = true --Disable cache to avoid altering timing calculations

  for i=1,iterations do
    local time_req = os.clock()
    --We don't care about the response, we are just measuring response times
    if bad_proxy then
      opts["header"]["Proxy"] = stdnse.generate_random_string(12)
      _ = http.get(host, port, path, opts)
    else
      _ = http.get(host, port, path, opts)
    end
    local time_resp = os.clock()
    total_time = total_time + (time_resp - time_req)
  end
  
  stdnse.debug1("Total time:%f Average:%f", total_time, total_time/iterations)
  return total_time/iterations
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local req_count = stdnse.get_script_args(SCRIPT_NAME..".iterations") or 10
  local test_count = stdnse.get_script_args(SCRIPT_NAME.."tests") or 3
  local output = stdnse.output_table()
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'HTTPoxy',
    state = vulns.STATE.NOT_VULN,
    description = [[
This web application might be affected by the vulnerability known as HTTPoxy. It seems the 
application is reading an arbitrary proxy value from the request headers.
    ]],
    references = {
      'https://httpoxy.org'
    },
    dates = {
      disclosure = {year = '2016', month = '07', day = '18'},
    },
  }
  local good_avg = nil
  local bad_avg = nil

  --Let's reduce false positives by running the test several times
  local inconsistent = false
  for i=1,test_count do --We always should get a larger avg in bad requests
    good_avg = get_avg(host, port, path, req_count, false)
    bad_avg = get_avg(host, port, path, req_count, true)
    if good_avg > bad_avg then
      inconsistent = true
    end
  end

  if not(inconsistent) then
    stdnse.debug1("Web application might be vulnerable to HTTPoxy")
    vuln.state = vulns.STATE.VULN
    vuln.extra_info = string.format("Avg response:%f Avg response with bad proxy:%f", good_avg, bad_avg)
  end

  return vuln_report:make_output(vuln)
end
