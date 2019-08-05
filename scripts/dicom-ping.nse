description = [[
Attempts to discover DICOM servers (DICOM Service Provider) through a partial C-ECHO request.

C-ECHO requests are commonly known as DICOM ping as they are used to test connectivity.
Normally, a 'DICOM ping' is formed as follows:
* Client -> A-ASSOCIATE request -> Server
* Server -> A-ASSOCIATE ACCEPT/REJECT -> Client
* Client -> C-ECHO request -> Server
* Server -> C-ECHO response -> Client
* Client -> A-RELEASE request -> Server
* Server -> A-RELEASE response -> Client

For this script we only send the A-ASSOCIATE request and look for the success code in the response as it seems to be a reliable way of detecting the devices.
]]

---
-- @usage nmap -p4242 --script dicom-ping <target>
-- @usage nmap -sV --script dicom-ping <target>
-- 
-- @output
-- PORT     STATE SERVICE REASON
-- 4242/tcp open  dicom   syn-ack
-- |_dicom-ping: DICOM DSP discovered
---

author = "Paulino Calderon <calderon()calderonpale.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "default"}

local shortport = require "shortport"
local dicom = require "dicom"
local stdnse = require "stdnse"
local nmap = require "nmap"

portrule = shortport.port_or_service({104, 2345, 2761, 2762, 4242, 11112}, "dicom", "tcp", "open")

action = function(host, port)
  local dcm_conn_status, err = dicom.associate(host, port)
  if dcm_conn_status == false then
    stdnse.debug1("Association failed:%s", err)
    if nmap.verbosity() > 1 then
      return string.format("Association failed:%s", err)
    else
      return nil
    end
  end
  port.version.name = "dicom"
  port.version.product = "DICOM SCP"
  nmap.set_port_version(host, port)
  
  return "DICOM SCP discovered" 
end
