-- Decodes every sample with the generated Lua code and compares the result with
-- its golden file in tests/expected/ (made by scripts/gen_expected.py).
--
--   lua test_samples.lua [luaunit options]     (from tests/lua; scripts/run_tests.py does this)
--
-- Needs generated/ (python scripts/compile.py --target lua) and vendor/ (the
-- Kaitai Lua runtime, luaunit and dkjson; scripts/run_tests.py fetches them).

local sep = package.config:sub(1, 1)
local here = (arg and arg[0] or ""):match("^(.*)[/\\]") or "."
package.path = table.concat({
  here .. "/?.lua", here .. "/generated/?.lua", here .. "/vendor/?.lua", package.path,
}, ";")

-- The generated modules require each other in a cycle (upstream ipv4_packet and
-- protocol_body import each other), and Lua 5.2+ `require` recurses forever on
-- a cycle. The modules only define globals, so this searcher marks a generated
-- module as loaded before running it, as Python does with import cycles. Only
-- the decode tests do this; scripts/build_check.py loads them with plain
-- `require` and so still reports the cycle.
table.insert(package.searchers, 2, function(name)
  local file = package.searchpath(name, here .. "/generated/?.lua")
  if not file then return nil end
  local chunk = assert(loadfile(file))
  return function()
    package.loaded[name] = true
    chunk(name, file)
    return true
  end, file
end)

local lu = require("luaunit")
local json = require("dkjson")
local json_diff = require("json_diff")

-- If the generated code doesn't load (a syntax error, say), report that as a
-- failing test, not a traceback.
local loaded, summary = pcall(require, "pcapng_summary")
if not loaded then
  TestGeneratedCode = {}
  function TestGeneratedCode:test_loads()
    lu.fail("the generated Lua code doesn't load: " .. tostring(summary))
  end
  os.exit(lu.LuaUnit.run())
end

local function path_join(...) return table.concat({ ... }, sep) end

local repo = os.getenv("PCAPNG_REPO_DIR") or path_join(here, "..", "..")
local samples_dir = os.getenv("PCAPNG_SAMPLES_DIR") or path_join(repo, "samples")
local expected_dir = os.getenv("PCAPNG_EXPECTED_DIR") or path_join(repo, "tests", "expected")

-- The standard library can't list a directory, so ask the shell.
local function sample_names()
  local cmd
  if sep == "\\" then
    cmd = 'dir /b "' .. samples_dir .. '\\*.pcapng" 2>nul'
  else
    cmd = 'ls "' .. samples_dir .. '" 2>/dev/null'
  end
  local names = {}
  local p = io.popen(cmd)
  if p then
    for line in p:lines() do
      local n = line:match("^(.-)%.pcapng%s*$")
      if n then names[#names + 1] = n end
    end
    p:close()
  end
  table.sort(names)
  return names
end

local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local s = f:read("a")
  f:close()
  return s
end

local function assert_json(want, got, what, opts)
  local diffs = json_diff.differences(want, got, opts)
  if #diffs > 0 then
    lu.fail(what .. " differs:\n  " .. table.concat(diffs, "\n  "))
  end
end

local names = sample_names()

TestSamples = {}
function TestSamples:test_finds_samples()
  lu.assertTrue(#names > 0, "no samples in " .. samples_dir)
end

for _, name in ipairs(names) do
  -- Parse lazily, so a parse failure fails that sample's tests and doesn't stop the run.
  local cache = {}
  local function expected(key)
    if cache.expected == nil then
      local golden = path_join(expected_dir, name .. ".json")
      local text = read_file(golden)
      if not text then
        lu.fail("no golden file " .. golden .. "; run: python scripts/gen_expected.py " .. name)
      end
      cache.expected = json.decode(text, 1, json.null)
    end
    return cache.expected[key]
  end
  local function parsed()
    if cache.parsed == nil then cache.parsed = Pcapng:from_file(path_join(samples_dir, name .. ".pcapng")) end
    return cache.parsed
  end
  local function actual(key)
    if cache.summary == nil then cache.summary, cache.packet_data = summary.summarize(parsed()) end
    return cache.summary[key]
  end

  local t = {}
  function t:test_parses_the_whole_file()
    lu.assertTrue(parsed()._io:is_eof(), "at end of file")
    assert_json(expected("file_size"), actual("file_size"), "file_size")
  end
  for _, key in ipairs({ "sections", "interfaces", "name_records", "interface_stats" }) do
    t["test_" .. key] = function() assert_json(expected(key), actual(key), key) end
  end
  function t:test_blocks()
    -- Lua has no number for an unknown enum value, so "0x..." names become "unknown".
    local want = {}
    for i, b in ipairs(expected("blocks")) do
      want[i] = b:match("^0x") and "unknown" or b
    end
    assert_json(want, actual("blocks"), "blocks")
  end
  function t:test_packets()
    -- The link-layer fields are checked in test_link_frames.
    assert_json(expected("packets"), actual("packets"), "packets",
      { ignore = function(p) return p:match("^%[%d+%]%.link$") ~= nil end })
  end
  function t:test_link_frames()
    local packets = expected("packets")
    actual("packets")
    local data = cache.packet_data
    lu.assertEquals(#data, #packets, "packets with data")
    local want, got = {}, {}
    for i, pd in ipairs(data) do
      local where = string.format("packet %d (link type %s)", i, tostring(pd.link_type))
      -- tshark leaves a field out (null) when it can't decode it; only compare what it gave.
      local golden = {}
      for k, v in pairs(packets[i].link) do
        if v ~= json.null then golden[k] = v end
      end
      local ok, fields = pcall(summary.link_fields, pd.link_type, pd.data)
      if not ok then lu.fail(where .. ": link_frame failed to parse: " .. tostring(fields)) end
      if pd.link_type == 1 then
        -- Every ether type in the samples should be named in ethernet_frame's
        -- ether_type_enum (the fork adds 0x88dc, wsmp).
        lu.assertNotNil(fields.ether_type_name, string.format("%s: ether type 0x%04x isn't in ether_type_enum",
          where, golden.ether_type or 0))
      end
      want[i], got[i] = golden, fields
    end
    -- ether_type_name, and fields tshark didn't give, are extra in got.
    assert_json(want, got, "link fields", { ignore_extra_fields = true })
  end
  _G["TestSample_" .. name:gsub("[^%w]", "_")] = t
end

os.exit(lu.LuaUnit.run())
