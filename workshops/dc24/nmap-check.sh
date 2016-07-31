#!/bin/bash

PEP8=$(which pep8)

if [ -z $PEP8 ]; then
  echo "No pep8 in your path. Skipping Python checks"
else
  for file in $(find "$@" -name '*.py'); do
    OUTPUT=$(mktemp)
    "$PEP8" -r "$file" > "$OUTPUT"
    if [ -s "$OUTPUT" ]; then
      cat "$OUTPUT" > /dev/stderr
      rm -f "$OUTPUT"
      exit 1
    fi
    rm -f "$OUTPUT"
  done
fi

# Lua checks stolen from/based on nse_check_globals by Patrick Donnelly
if [ -n "$LUA" ]; then
  if ! "$LUA" -v 2>&1 | grep 5.2 > /dev/null; then
    echo Lua 5.2 required. Skipping Lua checks.
  fi
elif ! lua -v 2>&1 | grep 5.2 > /dev/null; then
  echo Lua 5.2 required. Skipping Lua checks.
else
  LUA=$(which lua)
fi

if [ -n "$LUAC" ]; then
  if ! "$LUAC" -v 2>&1 | grep 5.2 > /dev/null; then
    echo Luac 5.2 required. Skipping Lua checks.
  fi
elif ! luac -v 2>&1 | grep 5.2 > /dev/null; then
  echo Luac 5.2 required. Skipping Lua checks.
else
  LUAC=$(which luac)
fi

export LUA
export LUAC

if [ -n "$LUA" -a -n "$LUAC" ]; then
  TOPDIR=$(pwd)
  NSE_LIBRARIES=""
  for lib in "$TOPDIR"/nselib/*.luadoc; do
    NSE_LIBRARIES="$NSE_LIBRARIES$(basename "$lib" .luadoc)"$'\n'
  done
  for lib in "$TOPDIR"/nselib/*.lua; do
    NSE_LIBRARIES="$NSE_LIBRARIES$(basename "$lib" .lua)"$'\n'
  done
  export NSE_LIBRARIES

  for file in $(find "$@" -name '*.nse' -o -name '*.lua'); do
    OUTPUT=$(mktemp)
    "$LUAC" -l -p "$file" > /dev/null 2> "$OUTPUT"
    if [ -s "$OUTPUT" ]; then
      sed "s|^$LUAC: ||" < "$OUTPUT" > /dev/stderr
      rm -f "$OUTPUT"
      exit 1
    fi
    rm -f "$OUTPUT"
    "$LUA" - "$file" <<EOF
local NSE_LIBRARIES = "\\n"..os.getenv("NSE_LIBRARIES").."\\n"; -- add delimiters
local LUA_LIBRARIES = {
  string = true,
  debug = true,
  package = true,
  _G = true,
  io = true,
  os = true,
  table = true,
  math = true,
  coroutine = true,
  bit32 = true,
};
IGNORE = {
  _M = true,
  _NAME = true,
  _PACKAGE = true,
};
local file = arg[1];
arg = nil; -- clear from global namespace

if not file or not io.open(file, "r") then
  io.stdout:write("no file argument specified.\\n");
  os.exit(1);
end

local command = os.getenv "LUAC" .. " -l -p " .. file .. "\\n";

local required = {};
local get_globals = {};
local set_globals = {};
local main_set = {};
if ("$file"):match ".nse\$" then
  main_set.SCRIPT_NAME = true;
  main_set.SCRIPT_PATH = true;
  main_set.SCRIPT_TYPE = true;
end
local main = true;
local first_loc = 1;
local registers = {};
local required_fields = {description = false; author = false; license = false; categories = false};
local exit_status = 0;
for line in assert(io.popen(command)):lines() do

  if main and line:find "^function" then
    main = false;
  end

  -- sometimes we see this:
  -- 428 [4680]  LOADK       12 -258 ; "get_pad"
  -- 429 [4683]  CLOSURE     13 67   ; 0xcf41e0
  -- 430 [4680]  SETTABUP    0 12 13 ; _ENV
  -- We must sadly save what constants are loaded into registers (simply)
  -- to determine what the key is for SETTABUP. There is no need to clear
  -- the registers.
  local r, constant = line:match("^%s%d+%s%[%d+%]%sLOADK%s+(%d+).-; \\"([%w_]+)\\"");
  if constant then
    registers[r] = constant;
  end

  local get_n, get_global = line:match("^%s%d+%s%[(%d+)%]%sGETTABUP.-; _ENV \\"([%w_]+)\\"");
  if not get_n then
    local r;
    get_n, r = line:match("^%s%d+%s%[(%d+)%]%sGETTABUP%s+%d+%s+%d+%s+(%d+).-; _ENV");
    if r then
      get_global = registers[r];
      if not get_global then get_n = nil end
    end
  end
  local set_n, set_global = line:match("^%s%d+%s%[(%d+)%]%sSETTABUP.-; _ENV \\"([%w_]+)\\"");
  if not set_n then
    local r;
    set_n, r = line:match("^%s%d+%s%[(%d+)%]%sSETTABUP%s+%d+%s+(%d+).-; _ENV");
    if r then
      set_global = registers[r];
      if not set_global then set_n = nil end
    end
  end
  if get_n then
    if IGNORE[get_global] then
      -- ignore it
    elseif NSE_LIBRARIES:find("\\n"..get_global.."\\n", 1, true) or LUA_LIBRARIES[get_global] then
      -- found global library, needs to be required
      --io.stdout:write("found global library ", get_global);
      if not required[get_global] then
        required[get_global] = get_n;
        required[#required+1] = get_global;
      end
    elseif _G[get_global] then
      -- found global Lua function, this is okay
      --io.stdout:write("found global ", get_global);
    else
      -- found global which may be "set", so we wait to report it
      if not get_globals[get_global] then
        get_globals[get_global] = get_n;
      end
      --io.stdout:write("found other global ", get_global);
    end
  elseif set_n then
    if main then
      -- Setting globals in main is okay.
      main_set[set_global] = true;
      --io.stdout:write("found main set global ", set_global);
    else
      -- Add to list of globals set which may be errors.
      if not set_globals[set_global] then
        set_globals[set_global] = set_n;
      end
      --io.stdout:write("found set global ", set_global);
    end
  end
  ::next_line::
end

-- go through list of libraries that need required, emit a patch
if next(required) then
  exit_status = 1
  table.sort(required);
  for i, global in ipairs(required) do
    local line = required[global];
    io.stdout:write("$file:", line, ": Found unrequired NSE library \\"", global, "\\".\\n");
  end
end
-- go through list of get_globals, if not in main_set, then error
for global, line in pairs(get_globals) do
  if main_set[global] then
    -- user is getting a global variable which we consider okay
    -- since this global was set previously in the main function
  else
    exit_status = 1
    io.stdout:write("$file:", line, ": Found bad indexed global \\"", global, "\\".\\n");
  end
end
-- go through list of set_globals, if not in main_set, then error
for global, line in pairs(set_globals) do
  if main_set[global] then
    -- user is setting a global variable which we consider okay
    -- since this global was set previously in the main function
  else
    exit_status = 1
    io.stdout:write("$file:", line, ": Found bad set global \\"", global, "\\".\\n");
  end
end
os.exit(exit_status)
EOF
  done
fi

exit 0
