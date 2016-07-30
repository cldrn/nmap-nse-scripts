local brute = require "brute"
local http = require "http"
local creds = require "creds"
local stdnse = require "stdnse"
local shortport = require "shortport"

description=[[

]]

author = ""
license = ""
categories = {"brute"}

Driver = {
  new = function(self, host, port)
  local o = {}
  setmetatable(o, self)
  self.__index = self
  o.host = host
  o.port = port
  return o
  end,

  connect = function(self)
  end,

  disconnect = function(self)
  end,

  login = function(self, username, password)

  end,
  check = function(self)

  end
}

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine:setMaxThreads(3)
  engine.options.script_name = SCRIPT_NAME

  local status, result = engine:start()

  return result
end
