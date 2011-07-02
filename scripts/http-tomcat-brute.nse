description = [[
Performs a brute force password attack against Apache Tomcat installations.

Tomcat default:
* uri: <code>/manager/html</code>
]]

---
-- @usage
-- ./nmap --script http-tomcat-brute --script-args 'http-tomcat-brute.hostname=192.168.1.105,http-tomcat-brute.threads=8' 192.168.1.105
--
-- @output
-- PORT   STATE SERVICE REASON
-- 8180/tcp open  unknown syn-ack
-- | http-tomcat-brute: 
-- |   Accounts
-- |     tomcat:tomcat => Login correct
-- |   Statistics
-- |_    Perfomed 15 guesses in 1 seconds, average tps: 15
--
--
-- @args http-tomcat-brute.uri Uri pointing to protected admin section. Default: /manager/html
-- @args http-tomcat-brute.hostname Sets hostname header.
-- @args http-tomcat-brute.threads Sets number of concurrent threads. Default: 3
--
-- Other useful arguments when using this script are:
-- * http.useragent = String - User Agent used in HTTP requests
-- * brute.firstonly = Boolean - Stop attack when the first credentials are found
-- * brute.mode = user/creds/pass - Username password iterator
-- * passdb = String - Path to password list 
-- * userdb = String - Path to user list 
--
author = "Paulino Calderon"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "auth", "intrusive"}

require "shortport"
require "http"
require "stdnse"
require "brute"

portrule = shortport.http

local DEFAULT_TOMCAT_URI = "/manager/html"
local DEFAULT_THREAD_NUM = 3

---
--This class implements the Driver class from the Brute library
---
Driver = {	
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = nmap.registry.args['http-tomcat-brute.hostname'] or host
    o.port = port
    o.uri = nmap.registry.args['http-tomcat-brute.uri'] or DEFAULT_TOMCAT_URI
    o.options = options
    return o
  end,
	
  connect = function( self )
    return true
  end,
	
  login = function( self, username, password)
    local credentials = {username = username, password = password}
    local response = http.get(self.host, self.port, self.uri, {auth = credentials, no_cache = true})
    stdnse.print_debug(2, "HTTP GET %s%s returned status %d", self.host, self.uri, response.status)
    if response.status ~= 401 and response.status ~= 403 then
      if ( not( nmap.registry['credentials'] ) ) then
        nmap.registry['credentials'] = {}
      end
      if ( not( nmap.registry.credentials['http'] ) ) then
        nmap.registry.credentials['http'] = {}
      end
		  
      table.insert( nmap.registry.credentials.http, { username = username, password = password } )
      return true, brute.Account:new( username, password, "OPEN")
    end
    return false, brute.Error:new( "Incorrect password" )
  end,
	
  disconnect = function( self ) 
    return true
  end,
	
  check = function( self )
    local response = http.get( self.host, self.port, self.uri )
    stdnse.print_debug(1, "HTTP GET %s%s", stdnse.get_hostname(self.host),self.uri)			
    -- Check if www-authenticate field is there
    if response.status == 401 and response.header["www-authenticate"] then
      stdnse.print_debug(1, "Initial check passed. Launching brute force attack")
      return true
    else
      stdnse.print_debug(1, "Initial check failed. Password field wasn't found")
    end
          
   return false
  end	
}
---
--MAIN
---
action = function(host, port)
  local status, result, engine
  local thread_num = nmap.registry["http-tomcat-brute.threads"] or DEFAULT_THREAD_NUM

  engine = brute.Engine:new( Driver, host, port )
  engine:setMaxThreads(thread_num)
  status, result = engine:start()
	
  return result
end
