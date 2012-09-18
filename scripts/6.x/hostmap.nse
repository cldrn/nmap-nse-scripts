description = [[
Finds hostnames that resolve to the target's IP address by querying the online databases:
* http://www.bfk.de/bfk_dnslogger.html 
* http://www.ip2hosts.com ( Bing Search Results )

Optionally users can return results from a specific provider by using the argument <code>hostmap.provider</code>. 
The supported provider identifiers are:
* BFK
* IP2HOSTS

The script is in the "external" category because it sends target IPs to a third party in order to query their database.
]]

---
-- @args hostmap.prefix If set, saves the output for each host in a file
-- called "<prefix><target>". The file contains one entry per line.
-- @args newtargets If set, add the new hostnames to the scanning queue.
-- This the names presumably resolve to the same IP address as the
-- original target, this is only useful for services such as HTTP that
-- can change their behavior based on hostname.
-- @args hostmap.provider If set, hostmap will only return results from
-- the given provider. By default it uses all the providers available and
-- merges the results. 
-- Supported providers: BFK, BING
--
-- @usage
-- nmap --script hostmap --script-args 'hostmap.prefix=hostmap-,hostmap.provider=BING' <targets>
--
-- @output
-- Host script results:
-- | hostmap: Saved to hostmap-nmap.org
-- | insecure.org
-- | 74.207.254.18
-- | web.insecure.org
-- | download.insecure.org
-- | images.insecure.org
-- | www.insecure.org
-- | nmap.org
-- | www.nmap.org
-- | sectools.org
-- | mirror.sectools.org
-- | www.sectools.org
-- |_seclists.org

author = {'Ange Gutek', 'Paulino Calderon'}

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"external", "discovery", "intrusive"}

local dns = require "dns"
local ipOps = require "ipOps"
local http = require "http"
local stdnse = require "stdnse"
local target = require "target"

local HOSTMAP_BFK_SERVER = "www.bfk.de"
local HOSTMAP_BING_SERVER = "www.ip2hosts.com"
local HOSTMAP_DEFAULT_PROVIDER = "ALL"

local filename_escape, write_file

hostrule = function(host)
  return not ipOps.isPrivate(host.ip)
end

local function query_bfk(ip) 
  local query = "/bfk_dnslogger.html?query=" .. ip
  local response
  local hostnames = {}
  response = http.get(HOSTMAP_BFK_SERVER, 80, query)

  if not response.status then
    return string.format("Error: could not GET http://%s%s", HOSTMAP_BFK_SERVER, query)
  end

  for entry in string.gmatch(response.body, "#result\">([^<]-)</a>") do
    if not hostnames[entry] then
      if target.ALLOW_NEW_TARGETS then
        local status, err = target.add(entry)
      end
      hostnames[entry] = true
      if string.match(entry, "%d+%.%d+%.%d+%.%d+") or dns.query(entry) then
        hostnames[#hostnames + 1] = entry
      else
        hostnames[#hostnames + 1] = entry .. " (cannot resolve)"
      end
    end
  end

  if #hostnames == 0 then
    if not string.find(response.body, "<p>The server returned no hits.</p>") then
      return "Error: found no hostnames but not the marker for \"no hostnames found\" (pattern error?)"
    end
  end
  return hostnames
end

local function query_bing(ip) 
  local query = "/csv.php?ip=" .. ip
  local response
  local entries
  response = http.get(HOSTMAP_BING_SERVER, 80, query)
  local hostnames = {}
  if not response.status then
    return string.format("Error: could not GET http://%s%s", HOSTMAP_BING_SERVER, query)
  end
  entries = stdnse.strsplit(",", response.body);
  for _, entry in pairs(entries) do
    if not hostnames[entry] and entry ~= "" then
      if target.ALLOW_NEW_TARGETS then
        local status, err = target.add(entry)
      end
      hostnames[#hostnames + 1] = entry
    end
  end

  if #hostnames == 0 then
    if not string.find(response.body, "no results") then
      return "Error: found no hostnames but not the marker for \"no hostnames found\" (pattern error?)"
    end
  end
  return hostnames
end

action = function(host)
  local filename_prefix = stdnse.get_script_args("hostmap.prefix")
  local provider = stdnse.get_script_args("hostmap.provider") or HOSTMAP_DEFAULT_PROVIDER
  local hostnames = {}
  local hostnames_str, output_str 

 --select provider accordingly
  if provider == "BFK" then
      stdnse.print_debug(1, "Using database: %s", HOSTMAP_BFK_SERVER)
      hostnames = query_bfk(host.ip)
  elseif provider == "BING" then
      stdnse.print_debug(1, "Using database: %s", HOSTMAP_BING_SERVER)
      hostnames = query_bing(host.ip)
  else 
      stdnse.print_debug(1, "Using all databases")
      local bing_hostnames = query_bing(host.ip)
      local bfk_hostnames = query_bfk(host.ip)
      local found
      --merge into same table
      local bing_hosts_type = type(bing_hostnames)
      local bfk_hosts_type = type(bfk_hostnames)
      --if one service does not respond, fail gracefully
      if bing_hosts_type == "table" and bfk_hosts_type == "table" then
        for k,bfk_host in pairs(bfk_hostnames) do
            found = false
            for _,bing_host in pairs(bing_hostnames) do
              if bfk_host == bing_host then
                found = true
              end
            end 
            if found == false and bfk_host ~= true then
              table.insert(bing_hostnames, bfk_host)
            end
        end
        hostnames = bing_hostnames
      elseif bing_hosts_type == "table" and bfk_hosts_type ~= "table" then
        stdnse.print_debug(1, "BFK did not return results.")
        hostnames = bing_hostnames
      elseif bing_hosts_type ~= "table" and bfk_hosts_type == "table" then
        stdnse.print_debug(1, "BING did not return results.")
        hostnames = bfk_hostnames
      end
  end

  if type(hostnames) == "string" then
    return hostnames
  end
  hostnames_str = stdnse.strjoin("\n", hostnames)

  --write to file
  if filename_prefix then
    local filename = filename_prefix .. filename_escape(host.targetname or host.ip)
    local status, err = write_file(filename, hostnames_str .. "\n")
    if status then
      output_str = string.format("Saved to %s\n", filename)
    else
      output_str = string.format("Error saving to %s: %s\n", filename, err)
    end
  else
    output_str = "\n"
  end

  output_str = output_str .. stdnse.strjoin("\n", hostnames)
  return output_str
end

-- Escape some potentially unsafe characters in a string meant to be a filename.
function filename_escape(s)
  return string.gsub(s, "[%z/=]", function(c)
    return string.format("=%02X", string.byte(c))
  end)
end

function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end
