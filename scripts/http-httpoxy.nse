local stdnse = require "stdnse"
local http = require "http"
local os = require "os"
local shortport = require "shortport"

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

local function req_poxy(host, port, path, opts)
  opts["header"]["Proxy"] = stdnse.generate_random_string(12)
  _ = http.get(host, port, path, opts)
  return nil 
end

local function get_avg(host, port, path, iterations, bad_proxy)
  local total_time = 0
  local opts = {header={}}
  opts["bypass_cache"] = true --Disable cache to avoid altering timing calculations

  for i=1,iterations do
    local time_req = os.clock()
    --We don't care about the response, we are just measuring response times
    if bad_proxy then
      req_poxy(host, port, path, opts)
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

  --Let's reduce false positives by running the test several times
  local inconsistent = false
  for i=1,test_count do --We always should get a larger avg in bad requests
    local good_avg = get_avg(host, port, path, req_count, false)
    local bad_avg = get_avg(host, port, path, req_count, true)
    if good_avg > bad_avg then
      inconsistent = true
    end
  end

  if not(inconsistent) then
    output.httpoxy = "Possibly vulnerable to HTTPoxy!"
  end

  return output
end
