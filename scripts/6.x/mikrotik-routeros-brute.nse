description = [[
Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled.

Additional information:
* http://wiki.mikrotik.com/wiki/API
* http://wiki.mikrotik.com/wiki/API_in_C
* https://github.com/mkbrutusproject/MKBRUTUS
]]

---
-- @usage
-- nmap -p8728 --script mikrotik-routeros-brute <target>
-- 
-- @output
--
-- @args mikrotik-routerous-brute.threads sets the number of threads. Default: 3
--
---

author = "Paulino Calderon <calderon()websec.mx>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "brute"}

local shortport = require "shortport"
local comm = require "comm"
local brute = require "brute"
local creds = require "creds"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"

portrule = shortport.portnumber(8728, "tcp")

--Brute object definition
Driver = 
{
  new = function(self, host, port, options )
  local o = { host = host, port = port, options = options }
  setmetatable(o, self)
  self.__index = self
    o.emptypass = true
    return o
  end,
	
  connect = function( self )
    self.s = nmap.new_socket("tcp")
    self.s:set_timeout(self.options['timeout'])
    return self.s:connect(self.host, self.port, "tcp")
  end,

  login = function( self, username, password )
    local status, data, try, ret
    data = bin.pack("cAx", 0x6,"/login")

    --Connect to service and obtain the challenge response
    try = nmap.new_try(function() return false, brute.Error:new( "Connection error" ) end)
    self.s:send(data)
    _, data = self.s:receive_bytes(50)
    stdnse.print_debug(1, "Response #1:%s", data)
    if type(data) == "string" then
      _, _, ret = string.find(data, '!done%%=ret=(.+)')
    end
    --If we find the challenge value we continue the connection process
    if ret then
        stdnse.print_debug(1, "Challenge value found:%s", ret)
        local md5str = bin.pack("xAA", password, ret:fromhex())
        local chksum = stdnse.tohex(openssl.md5(md5str))
        local login_pkt = bin.pack("cAcAcAx", 0x6, "/login", 0x0b, "=name="..username, 0x2c, "=response=00"..chksum)
        stdnse.print_debug(1, "%s:Login query:%s", SCRIPT_NAME, login_pkt)
        self.s:send(login_pkt)
        _, data = self.s:receive_bytes(50)
        stdnse.print_debug(1, "Response #2:%s", data)
        if data and string.find(data, "%!done") ~= nil then
          if string.find(data, "message=cannot") == nil then
            local c = creds.Credentials:new(SCRIPT_NAME, self.host, self.port )
            c:add(username, password, creds.State.VALID )
            return true, brute.Account:new(username, password, creds.State.VALID)
          end
        end
    end
    return false, brute.Error:new( "Incorrect password" )
  end,
  
  disconnect = function( self )
    return self.s:close()
  end		
}
function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

action = function(host, port)
  local result
  local thread_num = stdnse.get_script_args(SCRIPT_NAME..".threads") or 1
  local options = {timeout = 5000}
  local bengine = brute.Engine:new(Driver, host, port, options)

  bengine:setMaxThreads(thread_num)
  bengine.options.script_name = SCRIPT_NAME
  _, result = bengine:start()

  return result
end
