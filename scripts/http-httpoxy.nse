local stdnse = require "stdnse"
local http = require "http"
local os = require "os"
local shortport = require "shortport"

description=[[
Can we detect httpoxy measuring response timeouts?
]]

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
author = "Paulino Calderon <calderon()websec.mx>"
categories = {"vuln","discovery"}

portrule = shortport.http

local function req_poxy(host, port, path)
  local opts = {header={}}
  opts["bypass_cache"] = true --Disable cache to avoid altering timing calculations
  opts["header"]["Proxy"] = stdnse.generate_random_string(12)
  _ = http.get(host, port, path, opts)
  return nil -- We don't really care about the result, we are just measuring response times
end

local function bad_avg(host, port, path, iterations)
  stdnse.debug2("Calculating response time of bad requests")
  local total_time = 0
  for i=1,iterations do 
    local time_req = os.clock()
    req_poxy(host, port, path)
    local time_resp = os.clock()
    total_time = total_time + (time_resp - time_req)
  end
  
  stdnse.debug1("Total time:%f Average:%f", total_time, total_time/iterations)
  return total_time/iterations
end

local function good_avg(host, port, path, iterations)
  stdnse.debug2("Calculating response time of good requests")
  local total_time = 0
  local opts = {header={}}
  opts["bypass_cache"] = true --Disable cache to avoid altering timing calculations

  for i=1,iterations do 
    local time_req = os.clock()
    _ = http.get(host, port, path, opts)
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
    output.good = good_avg(host, port, path, req_count)
    output.bad = bad_avg(host, port, path, req_count)
    if output.good > output.bad then
      inconsistent = true
    end
  end

  if not(inconsistent) then
    output.httpoxy = "Possibly vulnerable to HTTPoxy!"
  end

  return output
end
