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

--Library Settings
local OPT_ALLOW_REMOTE = stdnse.get_script_args("httpspider.allowRemote") or false
local OPT_CACHE_CONTENT = stdnse.get_script_args("httpspider.cacheContent") or false
local OPT_SUBCRAWLERS_NUM = stdnse.get_script_args("httpspider.subcrawlers") or 3
local OPT_CRAWLER_DEPTH = stdnse.get_script_args("httpspider.depth") or 5
local OPT_PATH_BLACKLIST = stdnse.get_script_args("httpspider.pathBlacklist") or false

--Mutexes
local HTTPSPIDER_TBVL = {} --TBVL = To Be Visited List
local HTTPSPIDER_VL = {}  --VL = Visited List
local TBVL_MUTEX = nmap.object(HTTPSPIDER_TBVL)
local VL_MUTEX = nmap.object(HTTPSPIDER_VL)

--Adds uri to the Visited List page table stored in the registry
--URIs in the list have already been crawled.
--@param uri URI
local function vl_add(uri)
  VL_MUTEX "lock"
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
  if list_type == "TBVL" then
    TBVL_MUTEX "lock"
      return nmap.registry["httpspider"][SAVE_MODE][""]
    TBVL_MUTEX "done"
  else if list_type == "VL" then

  end
end

--Crawls given URL until it find all local links
--@return Table of crawled pages and its information
local function crawl(uri, options)

end

--Inits registry tables holding the tbvl and vl lists
--@see httspider.data
local function init_library_registry()
  if nmap.registry["httpspider.data"] then
    nmap.registry["httpspider.data"]["tbvl"] = {}
    nmap.registry["httpspider.data"]["vl"] = {}
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

--Returns base URL
--@return Base URL of address
local function get_base_url(url)
end

--Parses the href attribute of the <a> tags inside the given string
--@return list of href links
local function get_href_links(body)
        local href_links
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
