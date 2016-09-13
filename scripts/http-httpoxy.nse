local stdnse = require "stdnse"
local http = require "http"
local os = require "os"
local shortport = require "shortport"
local vulns = require "vulns"
local table = require "table"
local string = require "string"

description=[[
Attempts to detect web applications vulnerable to "httpoxy" (CVE-2016-5385, CVE-2016-5386,
CVE-2016-5387, CVE-2016-5388, CVE-2016-1000109, CVE-2016-1000110).

The script attempts to detect this vulnerability by measuring the response time when 
assigning a non-existing proxy to the headers. In theory, vulnerable applications will try 
to connect to the bad proxy increasing the response time. To reduce false positives we run 
the test several times and we expect the response time from the request with the bad 
proxy to be twice as big to get marked as vulnerable.   

References:
* https://httpoxy.org
]]

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
author = "Paulino Calderon <calderon()websec.mx>"
categories = {"vuln","exploit","intrusive"}

portrule = shortport.http

---
-- @usage
-- nmap -p80 --script http-httpoxy --script-args iterations=5 <target>
-- nmap -sV --script http-httpoxy <target>
--
-- @args http-httpoxy.path Path. Default: /
-- @args http-httpoxy.tests Number of tests used to measure average response time. Default: 30
-- @args http-httpoxy.threshold Detection threshold. Default: 2
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

local function time_requests(host, port, path)
  local opts = {header={}}
  opts["bypass_cache"] = true
  local time_req = nil
  local time_resp = nil
  local time_total = nil

  --Good request first
  time_req = os.clock()
  _ = http.get(host, port, path, opts)
  time_resp = os.clock()
  time_total = time_resp - time_req
  stdnse.debug1("Good request total time:%f", time_total)
  --Bad request
  opts["header"]["Proxy"] = string.format("%s.com", stdnse.generate_random_string(10))
  time_req = os.clock()
  _ = http.get(host, port, path, opts)
  time_resp = os.clock() 
  stdnse.debug1("Bad request total time:%f", time_resp - time_req)
  return time_total, (time_resp - time_req)
end

local function calculate_avg(t) 
  local entries = 0
  local sum = 0
  for _, v in pairs(t) do
    sum = sum + v
    entries = entries + 1
  end
  return (sum/entries)
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local test_count = stdnse.get_script_args(SCRIPT_NAME..".tests") or 30
  local detection_threshold = stdnse.get_script_args(SCRIPT_NAME..".threshold") or 2
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
  local good_reqs = {}
  local bad_reqs = {}

  --We measure the average time of good/bad requests
  for i=1,test_count do --We always should get a larger avg in bad requests
    good_avg, bad_avg = time_requests(host, port, path)
    table.insert(good_reqs, good_avg)
    table.insert(bad_reqs, bad_avg)
  end

  good_avg = calculate_avg(good_reqs)
  stdnse.debug1("Average response time for requests without proxy header:%f", good_avg)
  bad_avg = calculate_avg(bad_reqs)
  stdnse.debug1("Average response time for requests with Proxy header:%f", bad_avg)
  if bad_avg > ( good_avg * detection_threshold )then
    stdnse.debug1("Web application might be vulnerable to HTTPoxy")
    vuln.state = vulns.STATE.VULN
    vuln.extra_info = string.format("Avg response:%f Avg response with bad proxy:%f", good_avg, bad_avg)
  end

  return vuln_report:make_output(vuln)
end
