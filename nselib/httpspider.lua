---
-- HTTP Spidering Library
-- This library Implements an HTTP spider or web crawler. The information found by crawling a web server is useful to a 
-- variety of NSE HTTP scripts that perform tasks ranging from information gathering to web vulnerability exploitation.
--
-- @args httpspider.allowRemote Turn on to allow spider to crawl outside the parent website. Default value: false
-- @args httpspider.cacheContent Turn on to write cache files containing all the crawled page's content. Default value: false
--
-- @author Paulino Calderon
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--

local nmap = require "nmap";
local stdnse = require "stdnse";
local http = require "http";
local string = require "string";
module(... or "httpspider",package.seeall)

--Settings
local HTTPSPIDER_DATAKEY = "httpspider.data"
local OPT_ALLOW_REMOTE = stdnse.get_script_args("httpspider.allowRemote") or false
local OPT_CACHE_CONTENT = stdnse.get_script_args("httpspider.cacheContent") or false
local OPT_SUBCRAWLERS_NUM = stdnse.get_script_args("httpspider.subcrawlers") or 3
local OPT_CRAWLER_DEPTH = stdnse.get_script_args("httpspider.depth") or 5
local OPT_PATH_BLACKLIST = stdnse.get_script_args("httpspider.pathBlacklist") or false

--=============================================
--Queue implementation
--=============================================
--The following methods implement a FIFO queue
Queue = {}

--Initializes a new queue
--@return Index table
function Queue.new ()
  return {head = 0, tail = -1}
end

--Adds element to the queue
--Inserts are FIFO
--@param queue Queue
--@param value Value of new element
function Queue.add (queue, value)
  local last = queue.tail + 1
  queue.tail = last
  queue[last] = value
end

--Removes element from queue
--Deletions are FIFO
--@param queue Queue
--@return True if operation was succesfull
--@return Error string
function Queue.remove (queue)
  local first = queue.head
  if first > queue.tail then
    return false, "Queue is empty"
  end
  local value = queue[first]
  queue[first] = nil       
  queue.head = first + 1
  return true, value
end

--=========================================
--Mutexes
--=========================================
local HTTPSPIDER_TBVL = Queue.new() --TBVL = To Be Visited List
local HTTPSPIDER_VL = Queue.new()  --VL = Visited List
local TBVL_MUTEX 
local VL_MUTEX

--=========================================
---Crawler implementation
--=========================================

--Adds uri to the Visited List page table stored in the registry
--URIs in the list have already been crawled.
--@param uri URI
local function vl_add(uri)
  VL_MUTEX "lock"
    Queue.add(HTTPSPIDER_VL, uri)
  if nmap.registry["httpspider.data"]["vl"][uri] == nil then
    nmap.registry["httpspider.data"]["vl"][uri] = true
  end
  VL_MUTEX "done"
end

--Adds URI to a list of URIs to be crawled stored in the registry
--@param uri URI
local function tbvl_add(uri)
  TBVL_MUTEX "lock"
  if nmap.registry["httspider.data"]["tbvl"][uri] == nil then
    nmap.registry["httpspider.data"]["tbvl"][uri] = true
  end 
  TBVL_MUTEX "done"
  return true
end

--Gets next entry on the list
--List type: TBVL and VL
--TBVL: To Be Visited List
--VL: Visited List
--@param list_type TBVL or VL
--@return URI string
local function get_next_uri(list_type)
  local next_uri
  if list_type == "TBVL" then
    TBVL_MUTEX "lock"
      for _, uri in pairs(nmap.registry["httpspider"]["tbvl"]) do
        if uri then
          next_uri = nmap.registry["httpspider"]["tbvl"][uri]
          nmap.registry["httpspider"]["tbvl"][uri] = nil

          return next_uri
        end
      end
    TBVL_MUTEX "done"
  else if list_type == "VL" then
    VL_MUTEX "lock"
      return nmap.registry["httpspider"][]
    VL_MUTEX "done"
  end
end

--Crawls given URL until it find all local links
--@return Table of crawled pages and its information
local function crawl(uri, options)
  init_registry()
end

--Inits registry tables holding the tbvl and vl lists
--@see httspider.data
local function init_registry()
  if nmap.registry[HTTPSPIDER_DATAKEY]["tbvl"] == nil or nmap.registry[HTTPSPIDER_DATAKEY]["vl"] == nil then
    nmap.registry[HTTPSPIDER_DATAKEY]["tbvl"] = Queue.new()
    nmap.registry[HTTPSPIDER_DATAKEY]["vl"] = Queue.new()
    TBVL_MUTEX = nmap.object(nmap.registry[HTTPSPIDER_DATAKEY]["tbvl"])
    VL_MUTEX = nmap.object(nmap.registry[HTTPSPIDER_DATAKEY]["vl"])
  end
end

---Extracts URIs from given document and returns table
-- if the given URI passes the filter rules
-- @param uri URI
-- @param settings Options table
-- 
local function url_extract(uri, settings)
  --checks if remote crawling is allowed
  if not(is_uri_local(uri)) and not( settings["allowRemote"] ) then
    return false, "AllowRemote is disabled. We cannot crawl the given uri"
  end

  local uri_page = http.get_url( uri )
  
end

--Initializes web crawling using the given settings.
--This funcion extracts the initial set of links and 
--create the subcrawlers.
--@param uri URI string
--@param settings Options table
--
local function init_crawler(uri, settings)
  local crawlers_num = OPT_SUBCRAWLERS_NUM
  local co = {} 

  --Extracts links from given url
  local urls = url_extract(uri, settings)

  --Wake subcrawlers
  for i=1,crawlers_num do
    co[i] = stdnse.new_thread(init_subcrawler, nil)
  end

end

--Initializes a subcrawler
--
local function init_subcrawler()
  local uri = get_next_uri("TBVL")

end

--Finds redirects in the response
--@return True if a redirect is found
local function find_redirect(header)

end

--Checks if URL is an absolute address
--@return True if "http://"/"https://" is found
local function is_url_absolute(url)
        if string.find(url, "http://") or string.find(url, "https://") then
                return true
        else
                return false
        end
end

--Checks if given string is a relative url
--@param url URL String
--@return True if url is a relative url
local function is_url_relative(url)
  if is_url_absolute(url) then
    return false
  end
  return true
end

--Returns the url including the script name without parameters.
--@param uri URL String
--@return URL without parameters
local function remove_query(uri)
  local url_frags, abs_url
  url_frags = url.parse(uri)
  if url_frags.scheme and url_frags.authority and url_frags.path then
    abs_url = url_frags.scheme.."://"..url_frags.authority..url_frags.path
  else
    abs_url = uri
  end
  return abs_url
end

---Checks if link is malformed
--
--This function looks for:
--*Links that are too long
--*Links containing html code
--*Links with mailto tags
--
--@param url URL String
--@return True if link seems malformed
local function is_link_malformed(url)
  --check for links that are too long
  if string.len(url)>100 then
    return true
  end
  --check if brackets are found (indicating html code in link)
  if string.find(url, "[<>]") ~= nil then
    return true
  end
  --check for mailto tag
  if string.find(url, "mailto:") ~= nil then
    return true
  end
  --check if its a javascript action
  if string.find(url, "javascript:") ~= nil then
    return true
  end
  return false
end

--Checks if link is local.
--@param url_parts
--@param host
--@return True if link is local
local function is_link_local(url_parts, host)
  if url_parts.authority and
    not(url_parts.authority == stdnse.get_hostname(host) or
        url_parts.authority == "www."..stdnse.get_hostname(host)) then
    return false
  end

  return true
end

--Returns base URL
--@return Base URL of address
local function get_base_url(url)
end

--Extracts file extension from URL
--@param uri URL String
--@return URL Extension
local function get_url_extension(uri)
  local page_ext, ext_offset, url_frags

  -- Parse file extension if available
  url_frags=url.parse(uri)
  if url_frags ~= nil then
    ext_offset = string.find(url_frags.path, "%.(.*)")
    if ext_offset ~= nil then
      page_ext = string.sub(url_frags.path, ext_offset)
    else
      page_ext = ""
    end
  end
 
  return page_ext
end

--Parses the href attribute of the <a> tags inside the body
--@param body HTML Body
--@return Table of href links found in document
local function get_href_links(body)
  local href_links = {}

  body = string.lower(body)
  for l in string.gfind(body, 'href%s*=%s*[\'"](%s*[^"^\']+%s*)[\'"]') do
    table.insert(href_links, l)
  end

  return href_links
end

--Downloads a page and processes its information
--@return Table containing all the page information
local function download_page(host, port, url)
	page_resp = http.get(host, port, url)
	
	-- Process & store page
	link_list[#link_list + 1] = {["uri"]=url, ["status"]=page_resp.status, ["checksum"]="",
			 ["ext"]="", ["type"]=page_resp.header["content-type"], ["content"]=page_resp.body}
 
end

--Returns a list with all the crawled pages and its information
--@return Table of crawled pages
local function get_page_list()
	return link_list
end

--Returns a list of all images found in the website
--@return List of images found in document
local function get_image_files()

end

--Returns a list of all javascript files found in the website
--@return List of js files in document
local function get_javascript_files()

end

