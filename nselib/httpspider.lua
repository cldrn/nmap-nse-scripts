---
-- HTTP Spidering Library
-- This library implements a HTTP spider or web crawler. The information found by crawling a web server is useful to a
-- variety of NSE HTTP scripts that perform tasks ranging from information gathering to web vulnerability exploitation.
--
-- The crawler will quit after certain amount of time depending on the timing template level:
-- *-T3 or less - 10 minutes
-- *-T4 - 5 minutes
-- *-T5 - 3 minutes
-- The timing template level is ignored if the argument <code>httpspider.timeLimit</code> is set. If <code>httpspider.timeLimit</code>
-- is set to 0, the spider will not exit until its done crawling the site.
--
-- Using this library:
-- To crawl a web server : <code>httpspider.crawl(host, port, uri)</code>
-- Afterwards, to retrieve a list of the absolute URIs found: <code>httpspider.get_sitemap()</code>
-- To see more example of usage, take a look at http-sitemap and http-phpselfxss.
--
-- OPTIONS:
--*<code>allowRemote</code> - If set it allows the crawler to visit remote sites.
--*<code>subcrawlerNum</code> - Sets the number of subcrawlers to start when crawling
--*<code>pathBlacklist</code> - Table of paths that are not allowed to be visited. Note that paths shouldnt start or end with "/" Ie.
--                          --script-args httpspider.pathBlacklist={"examples", "documentation/examples"}
--*<code>ignoreParams</code> - Removes query parameters before visiting a page
--*<code>showBinaries</code> - If set it shows binaries that were found
--*<code>uriBlacklist</code> - Table of URIs that are not allowed to be crawled. The library uses absolute uris internally so you must provide the URIs in absolute form as well.
--*<code>timeLimit</code> - Time limit before quitting
--*<code>statsLimit</code> - Time interval when debug stats are shown
--*<code>cookies</code> - Cookie string to be appended with every request.
--
-- More documentation can be found at: https://secwiki.org/w/Nmap/Spidering_Library
--
-- @args httpspider.allowRemoteURI Turn on to allow spider to crawl outside the parent website to remote sites. Default value: false
-- @args httpspider.cachePageContent Turn on to write cache files containing all the crawled page's content. Default value: true
-- @args httpspider.subcrawlerNum Sets the number of subcrawlers to use. Default: 3
-- @args httpspider.pathBlacklist Table of paths that are blacklisted. Default: nil
-- @args httpspider.ignoreParams If set, it removes the query parameters from URIs and process them without arguments. Useful when crawling forums or similar software
--                                                        that has a lot of links pointing to the same script but changing a numeric ID. Default: false
-- @args httpspider.showBinaries Shows binaries in the list of visited URIs. Otherwise binaries are not shown because they were not parsed by the crawler. Default: false
-- @args httpspider.uriBlacklist Table of absolute URIs that are blacklisted. Default: nil
-- @args httpspider.timeLimit Time limit before killing the crawler. Default: According to Nmap's timing template. Use 0 for unlimited time.
-- @args httpspider.statsInterval Time limit before reporting stats in debug mode. Default: 10
-- @args httpspider.cookies Cookie string to be appended with every request. Default: nil
--
-- @author Paulino Calderon
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--

local nmap = require "nmap";
local stdnse = require "stdnse";
local http = require "http";
local string = require "string";
local url = require "url";
module(... or "httpspider", package.seeall)

--Settings for web crawler:
local LIB_NAME = "httpspider"
local OPT_ALLOW_REMOTE = stdnse.get_script_args(LIB_NAME..".allowRemote") or false
local OPT_CACHE_CONTENT = stdnse.get_script_args(LIB_NAME..".cacheContent") or true
local OPT_SUBCRAWLERS_NUM = stdnse.get_script_args(LIB_NAME..".subcrawlerNum") or 3
local OPT_PATH_BLACKLIST = stdnse.get_script_args(LIB_NAME..".pathBlacklist") or false
local OPT_IGNORE_PARAMS = stdnse.get_script_args(LIB_NAME..".ignoreParams") or false
local OPT_SHOW_BINARIES = stdnse.get_script_args(LIB_NAME..".showBinaries") or false
local OPT_URI_BLACKLIST = stdnse.get_script_args(LIB_NAME..".uriBlacklist") or false
local OPT_TIMELIMIT = stdnse.get_script_args(LIB_NAME..".timeLimit") or false
local OPT_STATS_INTERVAL = stdnse.get_script_args(LIB_NAME..".statsInterval") or 10
local OPT_COOKIES = stdnse.get_script_args(LIB_NAME..".cookies") or nil
--Error msgs used by the URI filter
local URI_FILTER_MSG_MALFORMED = "URI seems malformed."
local URI_FILTER_MSG_REMOTE = "URI is remote and AllowRemoteURI is disabled."
local URI_FILTER_MSG_BLACKLISTED = "URI is blacklisted."
local URI_FILTER_MSG_PATHBLACKLISTED = "Path is blacklisted"
local URI_FILTER_MSG_BINARY = "URI is a binary file."

--Global Objects
local UNVISITED_QUEUE
local UNVISITED_LIST = {}
local BINARY_LIST = {}
local CRAWLER_BASEPATH = nil
local START_TIME = nil
local START_TIMEOUT = nil
local TIMEOUT_LIMIT = nil
local VISITED_COUNTER = 0
local VISITED_CACHE_COUNTER = 0
local TOTAL_URI_COUNTER = 0
--===============================================================
--Queue implementation
--===============================================================

--Initializes a new queue
--@return Index table
function queue_new ()
  return {head = 0, tail = -1}
end

--Adds element to the queue
--Inserts are FIFO
--@param queue Queue
--@param value Value of new element
function queue_add (queue, value)
  local last = queue.tail + 1
  queue.tail = last
  queue[last] = value
end

--Removes element from queue
--Deletions are FIFO
--@param queue Queue
--@return True if operation was succesfull
--@return Error string
function queue_remove (queue)
  local first = queue.head
  if first > queue.tail then
    return false, "Queue is empty"
  end
  local value = queue[first]
  queue[first] = nil
  queue.head = first + 1
  return true, value
end

--Returns true if queue is empty
--@param queue Queue
--@return True if given queue is empty
function queue_is_empty(queue)
  if queue.head > queue.tail then
    return true
  end
  return false
end


--===============================================================
--Crawler implementation starts here
--===============================================================

--Returns true if the page has been visited
--@param uri URI to check
--@return True if page has been visited already
local function is_visited(uri)
  if nmap.registry[LIB_NAME]["visited"][uri] == nil then
    return false
  end
  return true
end

--Adds uri to the Visited List page table stored in the registry
--URIs in the list have already been crawled.
--@param uri URI
local function add_visited_uri(uri, page_obj)
  stdnse.print_debug(3, "%s: Trying to add URI '%s' to the visited registry", LIB_NAME, uri)
  if nmap.registry[LIB_NAME]["visited"][uri] == nil then
    nmap.registry[LIB_NAME]["visited"][uri] = page_obj
    VISITED_COUNTER = VISITED_COUNTER + 1
    stdnse.print_debug(3, "%s: URI '%s' was added to the visited registry succesfully", LIB_NAME, uri)
    return
  end
    VISITED_CACHE_COUNTER = VISITED_CACHE_COUNTER + 1
    stdnse.print_debug(2, "%s: URI '%s' was found in registry", LIB_NAME, uri)
end

--Adds URI to a list of URIs to be crawled stored in the registry
--We use a local list to check if item is already in queue to obtain constant time.
--@param uri URI
local function add_unvisited_uri(uri)
  if UNVISITED_LIST[uri] == nil then
    UNVISITED_LIST[uri] = true
    queue_add(UNVISITED_QUEUE, uri)
    stdnse.print_debug(3, "%s: NEW URI '%s' was added to unvisited queue", LIB_NAME, uri)
  end
end

--Parses a table of URIs and if the URI hasn't been visited,
--it adds it to the unvisited queue
--@param uris Table containing URIs
local function add_unvisited_uris(uris)
  for _, uri in pairs(uris) do
    if not( is_visited(uri) ) then
      add_unvisited_uri(uri)
    end
  end
end

--Adds URI of a binary file to the binary list
--@param uri URI
local function add_binary_uri(uri)
  if BINARY_LIST[uri] == nil then
    BINARY_LIST[uri] = true
  end
end

--Returns true if crawling is done
 --@return true if queue of pages to visit is empty
local function is_crawling_done()
  local ret = queue_is_empty(UNVISITED_QUEUE)
  stdnse.print_debug(3, "%s:is_crawling_done() -> %s", LIB_NAME, tostring(ret))
  return ret
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

--Returns URI's path
--@param url URL String
--@return Path string excluding basepath
local function get_current_path(host, uri)
  local base_path_frags, base_path_frags_num, path_frags, path_frags_num
  local current_path=""

  base_path_frags = url.parse_path("http://"..stdnse.get_hostname(host)..CRAWLER_BASEPATH)
  path_frags = url.parse_path(uri)
  base_path_frags_num = #base_path_frags
  path_frags_num = #path_frags
  for i = base_path_frags_num+1, path_frags_num-1, 1 do
    current_path = current_path..path_frags[i].."/"
  end
  if current_path == "" then
    current_path = "/"
  end
  stdnse.print_debug(2, "%s: get_current_path(%s):%s", LIB_NAME, uri, current_path)
  return current_path
end

--Parses URIs to make sure they are in the correct format
--@param uri URI
local function format_uri ( host, port, basepath_uri, uri )
  if not( is_url_absolute(uri) ) then
    local cur_path = get_current_path(host, basepath_uri)
    stdnse.print_debug(3, "%s: URI before formatting:%s", LIB_NAME, uri)
    uri = url.absolute(basepath_uri, uri)
    stdnse.print_debug(3, "%s: URI after formatting:%s", LIB_NAME, uri)
  end

  if OPT_IGNORE_PARAMS then
    uri = remove_query(uri)
  end

  return uri
end

--Checks if link is local.
--@param url_parts
--@param host
--@return True if link is local
local function is_uri_local(host, uri)
  local url_parts = url.parse(uri)

  if url_parts and url_parts.authority ~= nil and
    not(url_parts.authority == stdnse.get_hostname(host) or
        url_parts.authority == "www."..stdnse.get_hostname(host)) then
    return false
  end

  return true
end

--Checks if the given URI is blacklisted
--@param uri URI string
--@return True if URI is blacklisted
local function is_uri_blacklisted(uri)

  if OPT_URI_BLACKLIST and type(OPT_URI_BLACKLIST)=="table" then
    for i, bl_uri in pairs(OPT_URI_BLACKLIST) do
      if bl_uri == uri then
        return true
      end
    end
  end
  return false
end

--Checks if path is blacklisted
--@param uri URI string
--@return True if path appears on the blacklist
local function is_path_blacklisted(host, uri)
  if OPT_PATH_BLACKLIST and type(OPT_PATH_BLACKLIST) == "table" then
    local curpath = get_current_path(host, uri)
    for _, bpath in pairs(OPT_PATH_BLACKLIST) do
      if bpath.."/" == curpath then
        return true
      end
    end
  end
  return false
end

--Checks if link is malformed.
--This function looks for:
--*Links that are too long
--*Links containing html code
--*Links with mailto tags
--@param url URL String
--@return True if link seems malformed
local function is_uri_malformed(url)
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

--Checks if extension is blacklisted
--@param ext Url extension
--@return True if the url contains a invalid extension
local function is_ext_blacklisted(ext)
  local banned_extensions = {".exe", ".bat", ".com", ".jpg",".png",".gif", ".jpeg", ".sh",
                                                ".pdf",".doc",".docx",".ppt",".css",
                                                ".js", ".rar", ".zip",".tar.gz", ".swf",
                                                ".txt", ".mp3", ".au3", ".flv"}

  if ext then
    ext = string.lower(ext)
  end
  for _, banned_ext in pairs(banned_extensions) do
    if ext == banned_ext then
      return true
    end
  end

  return false
end

--Extracts file extension from URL
--@param uri URL String
--@return URL Extension
function get_uri_extension(uri)
  local page_ext, ext_offset, url_frags

  -- Parse file extension if available
  url_frags=url.parse(uri)
  if url_frags ~= nil and url_frags.path ~= nil then
    ext_offset = string.find(url_frags.path, "%.(.*)")
    if ext_offset ~= nil then
      page_ext = string.sub(url_frags.path, ext_offset)
    else
      page_ext = ""
    end
  end

  return page_ext
end

--This is the main URI filter. We use this function to check a given URI agaisnt a set of filters
--defined by the crawler options.
--It supports the following options/filters>
--* allowRemoteUri - Allows remote servers to be crawled
--* file extension
--@param uri URI
--@return true if the crawler is allowed to visit the given URI
local function uri_filter(host, uri)
  if not(is_uri_local(host, uri)) and not( OPT_ALLOW_REMOTE ) then
    return false, URI_FILTER_MSG_REMOTE
  end

  if is_uri_malformed(uri) then
    return false, URI_FILTER_MSG_MALFORMED
  end

  if is_uri_blacklisted(uri) then
    return false, URI_FILTER_MSG_BLACKLISTED
  end

  if is_path_blacklisted(host, uri) then
    return false, URI_FILTER_MSG_PATHBLACKLISTED
  end

  local ext = get_uri_extension(uri)
  if is_ext_blacklisted(ext) then
    return false, URI_FILTER_MSG_BINARY
  end

  return true
end

---Extracts URIs from given document and returns table
-- if the given URI passes the filter rules
-- @param uri URI
-- @param settings Options table
-- @param False is uri is not valid, otherwise a table containing the uris extracted
--
local function url_extract(host, port, uri)
  stdnse.print_debug(2, "%s:Extracting links from:%s", LIB_NAME, uri)
  local uricheck_b, uricheck_msg = uri_filter(host, uri)
  TOTAL_URI_COUNTER = TOTAL_URI_COUNTER + 1

  if not (uricheck_b) then
    stdnse.print_debug(3, "%s: URI '%s' did not pass the filter:%s", LIB_NAME, uri, uricheck_msg)
    if (uricheck_msg == URI_FILTER_MSG_BINARY ) and OPT_SHOW_BINARIES then
      add_binary_uri(uri)
    end

    return false
  end

  local formatted_links = {}
  local options = nil
  if OPT_COOKIES then
    options = {["cookies"]=string.format("%s", OPT_COOKIES)}
  end
  local page_obj = http.get(host, port, uri, options)
  if page_obj.status and ( page_obj.status > 300 and page_obj.status < 400 ) then
    if page_obj.header.location then
      formatted_links[#formatted_links+1] = format_uri(host, port, uri, page_obj.header.location)
    end
    return formatted_links
  end

  local page_obj_db = {["uri"]=uri, ["status"]=page_obj.status, ["type"]=page_obj.header["content-type"]}
  add_visited_uri(uri, page_obj_db)

  local links = get_href_links(page_obj.body)
  local src_links = get_src_links(page_obj.body)
  local form_links = get_form_links(page_obj.body)

  for i, href_link in pairs(links) do
    stdnse.print_debug(3, "%s:URI '%s' extracted from '%s'", LIB_NAME, href_link, uri)
    href_link = format_uri(host, port, uri, href_link)
    formatted_links[#formatted_links+1] = href_link
  end

  for i, src_link in pairs(src_links) do
    stdnse.print_debug(3, "%s:URI '%s' extracted from '%s'", LIB_NAME, src_link, uri)
    src_link = format_uri(host, port, uri, src_link)
    formatted_links[#formatted_links+1] = src_link
  end

  for i, action_link in pairs(form_links) do
    stdnse.print_debug(3, "%s:URI '%s' extracted from '%s'", LIB_NAME, action_link, uri)
    action_link = format_uri(host, port, uri, action_link)
    formatted_links[#formatted_links+1] = action_link
  end

  return formatted_links
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

--Checks if link is anchored ()
--Example: "#linkPointingInsideOfDocument"
--@param url URL String
--@return True if url is an anchored link
local function is_link_anchored(url)
  if string.sub(url, 1, 1) == "#" then
    return true
  end
  return false
end

--Parses the href attribute of the <a> tags inside the body
--@param body HTML Body
--@return Table of href links found in document
function get_href_links(body)
  local href_links = {}

  for l in string.gfind(body, 'href%s*=%s*[\'"](%s*[^"^\']+%s*)[\'"]') do
    table.insert(href_links, l)
  end

  return href_links
end

--Parses the src attribute of the <script> tags inside the document's body
--@param body HTML body
--@return Table of JS links found
function get_src_links(body)
  local src_links = {}

  for l in string.gfind(body, 'src%s*=%s*[\'"](%s*[^"^\']+%s*)[\'"]') do
    table.insert(src_links, l)
  end

  return src_links
end

--Parses the action attribute of the <form> tags inside the document's body
--@param body HTML body
--@return Table of links found
function get_form_links(body)
  local src_links = {}

  for l in string.gfind(body, 'action%s*=%s*[\'"](%s*[^"^\']+%s*)[\'"]') do
    table.insert(src_links, l)
  end

  return src_links
end

--Initializes registry keys to hold the visited list
--It uses the key [LIB_NAME]["visited"] to store a list of pages that have
--been parsed already.
local function init_registry()
  nmap.registry[LIB_NAME] = {}
  nmap.registry[LIB_NAME]["visited"] = {}
  nmap.registry[LIB_NAME]["finished"] = false
  nmap.registry[LIB_NAME]["running"] = true
end

--Reports stats of the web crawlers.
--It shows:
--*Visited URIs - Number of URIs that have been visited
--*Total extracted URIs - Total number of URIs found
--*Cache hits - Number of URIs that were going to be visited but they were found in the registry
local function report_stats()
  local time_diff = ( os.time() - START_TIME )
  if( time_diff > OPT_STATS_INTERVAL) then
    stdnse.print_debug(1, "%s: Stats -> Visited URIs: %d Total extracted URIs:%d Cache hits:%d", LIB_NAME, VISITED_COUNTER, TOTAL_URI_COUNTER, VISITED_CACHE_COUNTER)
    START_TIME = os.time()
  end
end

--Returns the amount of time before the crawler should quit
--It is based on Nmap's timing values -T4 or the OPT_TIMELIT if set
--@return Time limit before quitting crawling
local function get_timeout_limit()
  local timing_lvl = nmap.timing_level()
  local interval

  if timing_lvl <= 3 then
    interval = 600
  elseif timing_lvl ==4 then
    interval = 300
  elseif timing_lvl >= 5 then
    interval = 180
  end

  if OPT_TIMELIMIT then
      interval = OPT_TIMELIMIT
  end

  stdnse.print_debug(3, "%s:Crawler will quit after %s seconds", LIB_NAME, interval)
  return interval
end

--Checks if the crawler has been running longer than the timelimit
--If it has, it exits
local function has_crawler_timedout()
  local timediff = ( os.time() - START_TIMEOUT )
  if ( TIMEOUT_LIMIT ~= 0 and timediff > tonumber(TIMEOUT_LIMIT) ) then
    return true
  end
  return false
end

--
--Initializes a subcrawler
--A subcrawler will fetch an URI from the queue and extract new URIs, filter and add them to the queue.
--The thread will quit if the allowed running time has been exceeded.
--@param Host table
--@param Port table
local function init_subcrawler(host, port)
  stdnse.print_debug(3, "%s:STARTING SUBCRAWLER", LIB_NAME)
  local condvar = nmap.condvar(host)

  repeat
    --exit if crawler has timed out
    if has_crawler_timedout() then
      stdnse.print_debug(1, "%s:CRAWLER HAS TIMED OUT. EXITING...", LIB_NAME)
      return true
    end
    --Show periodic stats in debug output
    report_stats()
    --Process new item in queue
    local st, uri = queue_remove(UNVISITED_QUEUE)
    --If there was an item left on queue, we proceed to fetch it and extract new urls
    if st then
      local new_uris = url_extract(host, port, uri)
      if new_uris and #new_uris>0 then
        add_unvisited_uris(new_uris)
      end
    end
  until is_crawling_done()

  stdnse.print_debug(3,"%s:SUBCRAWLER EXITING...", LIB_NAME)
  return true
end

--Dumps the registry entries of visited sites
local function dump_visited_uris()
  stdnse.print_debug(1, "%s:Sitedump", LIB_NAME)
  for i, uri in pairs(nmap.registry[LIB_NAME]["visited"]) do
    stdnse.print_debug(1, "%s", uri["uri"])
  end
end

--Returns a table of URIs found in the web server
--@return Table of URIs found
function get_sitemap()
  local uris = {}
  for i, uri in pairs(nmap.registry[LIB_NAME]["visited"]) do
    uris[#uris+1] = uri["uri"]
  end
  if OPT_SHOW_BINARIES then
    for _, buri in pairs(BINARY_LIST) do
      if type( buri ) == "string" then
        uris[#uris+1] = buri
      end
    end
  end
  return uris
end

--Initializes the web crawler.
--This funcion extracts the initial set of links and
--creates the subcrawlers that start processing these links.
--It waits until all the subcrawlers are done before quitting.
--@param uri URI string
--@param settings Options table
local function init_crawler(host, port, uri)
  stdnse.print_debug(1, "%s:[Subcrawler] Crawling URI '%s'", LIB_NAME, uri)
  local crawlers_num = OPT_SUBCRAWLERS_NUM
  local co = {}
  local condvar = nmap.condvar(host)

  init_registry()

  --For consistency, transform initial URI to absolute form
  if not( is_url_absolute(uri) ) then
    local abs_uri = url.absolute("http://"..stdnse.get_hostname(host), uri)
    stdnse.print_debug(3, "%s:Starting URI '%s' became '%s'", LIB_NAME, uri, abs_uri)
    uri = abs_uri
  end

  --Extracts links from given url
  local urls = url_extract(host, port, uri)

  if #urls<=0 then
    stdnse.print_debug(3, "%s:0 links found in %s", LIB_NAME, uri)
    nmap.registry[LIB_NAME]["finished"] = true
    return false
  end

  add_unvisited_uris(urls)

  --Reduce the number of subcrawlers if the initial link list has less
  -- items than the number of subcrawlers
  if tonumber(crawlers_num) > #urls then
    crawlers_num = #urls
  end

  --Wake subcrawlers
  for i=1,crawlers_num do
    stdnse.print_debug(2, "%s:Creating subcrawler #%d", LIB_NAME, i)
    co[i] = stdnse.new_thread(init_subcrawler, host, port)
  end

  repeat
    condvar "wait";
    for i, thread in pairs(co) do
      if coroutine.status(thread) == "dead" then co[i] = nil end
    end
  until next(co) == nil;

  dump_visited_uris()
  nmap.registry[LIB_NAME]["finished"] = true
  nmap.registry[LIB_NAME]["running"] = false

end

--Crawls given URL until it follows all discovered URIs
--Several options can alter the behavior of the crawler, please
--take a look at the documentation closely.
--@param host Host table
--@param port Port table
--@param uri URI to crawl
function crawl(host, port, uri)
  if uri then
    if not(nmap.registry[LIB_NAME]) then
      stdnse.print_debug(1, "%s:Starting web crawler. URI:%s", LIB_NAME, uri)
      UNVISITED_QUEUE = queue_new()

      START_TIME = os.time()
      START_TIMEOUT = START_TIME
      CRAWLER_BASEPATH = uri
      TIMEOUT_LIMIT = get_timeout_limit()

      init_crawler(host, port, uri)
    else 
      stdnse.print_debug(1, "%s:Registry entry exists! (A crawler has been initiated)", LIB_NAME)
      while not(nmap.registry[LIB_NAME]["finished"]) do
        stdnse.print_debug(1, "%s:Another web crawler is running. Going to sleep now!", LIB_NAME)
        stdnse.sleep(3)
      end
    end
  end
end
