-- Turns a parsed Pcapng into the shape of tests/expected/<sample>.json.
-- Only the generated code reads the file; this reads the parsed object tree.
--
-- Differences from the other languages:
-- * An enum field with an unknown value is nil (the number is lost), as in Java.
--   An unknown block type is reported as "unknown".
-- * Lua integers are signed 64-bit, so ts_ns is computed with a small decimal
--   bignum and works for any u8 timestamp.

require("pcapng")
require("link_frame")
local json = require("dkjson")
local stringstream = require("string_stream")

local M = {}
local null = json.null

local ISB_COUNTERS = { [4] = "ifrecv", [5] = "ifdrop", [6] = "filteraccept", [7] = "osdrop", [8] = "usrdeliv" }
local BOM_LE = "\x4d\x3c\x2b\x1a"

local function array(t)
  return setmetatable(t or {}, { __jsontype = "array" })
end

local function opt(v)
  if v == nil then return null end
  return v
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- --- a minimal unsigned bignum: little-endian base-10^7 digits ---------------

local BASE = 10000000

local function bn_from_u32_pair(high, low)
  -- high * 2^32 + low; both fit easily in Lua's 64-bit integers.
  local n = { 0 }
  local function mul_add(m, add)
    local carry = add
    for i = 1, #n do
      local v = n[i] * m + carry
      n[i] = v % BASE
      carry = v // BASE
    end
    while carry > 0 do
      n[#n + 1] = carry % BASE
      carry = carry // BASE
    end
  end
  mul_add(1, high)
  mul_add(65536, 0)
  mul_add(65536, low)
  return n
end

local function bn_mul(n, m)  -- m < 2^31
  local carry = 0
  for i = 1, #n do
    local v = n[i] * m + carry
    n[i] = v % BASE
    carry = v // BASE
  end
  while carry > 0 do
    n[#n + 1] = carry % BASE
    carry = carry // BASE
  end
end

local function bn_div(n, d)  -- floor division by a small d (< 2^31)
  local rem = 0
  for i = #n, 1, -1 do
    local v = rem * BASE + n[i]
    n[i] = v // d
    rem = v % d
  end
  while #n > 1 and n[#n] == 0 do n[#n] = nil end
end

local function bn_add(a, b)  -- a + b, in place in a
  local carry = 0
  for i = 1, math.max(#a, #b) do
    local v = (a[i] or 0) + (b[i] or 0) + carry
    a[i] = v % BASE
    carry = v // BASE
  end
  if carry > 0 then a[#a + 1] = carry end
end

local function bn_sub(a, b)  -- a - b, in place in a; a must be >= b
  local borrow = 0
  for i = 1, #a do
    local v = a[i] - (b[i] or 0) - borrow
    if v < 0 then
      v = v + BASE
      borrow = 1
    else
      borrow = 0
    end
    a[i] = v
  end
  if borrow > 0 then error("negative timestamp") end
  while #a > 1 and a[#a] == 0 do a[#a] = nil end
end

local function bn_tostring(n)
  local parts = { tostring(n[#n]) }
  for i = #n - 1, 1, -1 do
    parts[#parts + 1] = string.format("%07d", n[i])
  end
  return table.concat(parts)
end

-- A timestamp in nanoseconds, from if_tsresol (10^-r, or 2^-r with the high bit
-- set) and if_tsoffset (seconds).
function M.ts_ns(ts_high, ts_low, tsresol, tsoffset)
  local n = bn_from_u32_pair(ts_high, ts_low)
  bn_mul(n, 1000000000)
  if tsresol & 0x80 ~= 0 then
    for _ = 1, tsresol & 0x7f do bn_div(n, 2) end
  else
    for _ = 1, tsresol do bn_div(n, 10) end
  end
  -- tsoffset * 1e9 can exceed 2^63, so it goes through the bignum too.
  -- (math.mininteger has no positive counterpart; no real offset is that big.)
  local mag = tsoffset < 0 and -tsoffset or tsoffset
  local off = bn_from_u32_pair(mag >> 32, mag & 0xffffffff)
  bn_mul(off, 1000000000)
  if tsoffset < 0 then bn_sub(n, off) else bn_add(n, off) end
  return bn_tostring(n)
end

-- --- the summary ----------------------------------------------------------------

local function entries(options)
  if options == nil or options.entries == nil then return {} end
  return options.entries
end

local function first_text(options, code)
  for _, o in ipairs(entries(options)) do
    if o.code == code then return o.value.value end
  end
  return null
end

local function comments(options)
  local out = array()
  for _, o in ipairs(entries(options)) do
    if o.code == 1 then out[#out + 1] = o.value.value end
  end
  return out
end

local function block_type_name(bt)
  -- bt is the enum entry, or nil for a value the enum doesn't have.
  if bt == nil then return "unknown" end
  return bt.label
end

local function packet(si, iface, interface_id, cap_len, orig_len, ts_high, ts_low, options)
  return {
    section = si,
    interface_id = interface_id,
    cap_len = cap_len,
    orig_len = orig_len,
    ts_ns = M.ts_ns(ts_high, ts_low, iface.tsresol, iface.tsoffset),
    comments = comments(options),
  }
end

-- Returns the summary (keys as in the golden file) and a list of
-- {link_type = ..., data = ...} for every packet.
function M.summarize(parsed)
  local sections, blocks, interfaces = array(), array(), array()
  local packets, names, stats = array(), array(), array()
  local ifaces, packet_data = {}, {}
  local total = 0
  local BT = Pcapng.BlockType

  for si0, sif in ipairs(parsed.sections) do
    local si = si0 - 1
    local sec = sif.section
    local shb = sec.header.body
    sections[#sections + 1] = {
      endian = (sif.byte_order_magic == BOM_LE) and "le" or "be",
      version = array({ shb.version_major, shb.version_minor }),
      section_length = shb.section_length,
      hardware = first_text(shb.options, 2),
      os = first_text(shb.options, 3),
      userappl = first_text(shb.options, 4),
      comments = comments(shb.options),
    }
    local first_iface = #ifaces

    local all = { sec.header }
    for _, b in ipairs(sec.blocks or {}) do all[#all + 1] = b end
    for _, b in ipairs(all) do
      total = total + b.len_block
      blocks[#blocks + 1] = block_type_name(b.block_type)
      local body = b.body
      local bt = b.block_type
      if bt == BT.interface_description then
        local tsresol, tsoffset
        for _, o in ipairs(entries(body.options)) do
          if o.code == 9 and tsresol == nil then tsresol = o.value.value end
          if o.code == 14 and tsoffset == nil then tsoffset = o.value.value end
        end
        local iface = {
          link_type = body.link_type and body.link_type.value or null,
          snaplen = body.snaplen,
          tsresol = tsresol or 6,
          tsoffset = tsoffset or 0,
        }
        ifaces[#ifaces + 1] = iface
        interfaces[#interfaces + 1] = {
          section = si,
          link_type = iface.link_type,
          snaplen = body.snaplen,
          name = first_text(body.options, 2),
          description = first_text(body.options, 3),
          tsresol = iface.tsresol,
          tsoffset = iface.tsoffset,
          comments = comments(body.options),
        }
      elseif bt == BT.enhanced_packet or bt == BT.packet then
        local iface = ifaces[first_iface + body.interface_id + 1]
        packets[#packets + 1] = packet(si, iface, body.interface_id, body.len_packet_data, body.len_original,
          body.ts_high, body.ts_low, body.options)
        packet_data[#packet_data + 1] = { link_type = iface.link_type, data = body.packet_data }
      elseif bt == BT.simple_packet then
        local iface = ifaces[first_iface + 1]
        local cap = math.min(body.len_original, #body.packet_data_and_padding)
        if iface.snaplen ~= 0 then cap = math.min(cap, iface.snaplen) end
        packets[#packets + 1] = {
          section = si, interface_id = 0, cap_len = cap, orig_len = body.len_original,
          ts_ns = null, comments = array(),
        }
        packet_data[#packet_data + 1] = { link_type = iface.link_type, data = body.packet_data_and_padding:sub(1, cap) }
      elseif bt == BT.name_resolution then
        for _, rec in ipairs(body.records) do
          if rec.record_type ~= 0 then
            if rec.record_type >= 1 and rec.record_type <= 4 then
              local ns = array()
              for _, n in ipairs(rec.value.names) do
                if n ~= "" then ns[#ns + 1] = n end
              end
              names[#names + 1] = { record_type = rec.record_type, address = hex(rec.value.address), names = ns }
            else
              names[#names + 1] = { record_type = rec.record_type, value = hex(rec.value) }
            end
          end
        end
      elseif bt == BT.interface_statistics then
        local st = { section = si, interface_id = body.interface_id, ts_high = body.ts_high, ts_low = body.ts_low }
        for _, o in ipairs(entries(body.options)) do
          if (o.code == 2 or o.code == 3) and o.value.ts_high ~= nil then
            st[o.code == 2 and "starttime" or "endtime"] = array({ o.value.ts_high, o.value.ts_low })
          elseif ISB_COUNTERS[o.code] and o.value.value ~= nil then
            st[ISB_COUNTERS[o.code]] = o.value.value
          elseif o.code == 1 then
            st.comments = st.comments or array()
            st.comments[#st.comments + 1] = o.value.value
          end
        end
        stats[#stats + 1] = st
      end
    end
    for _, sk in ipairs(sec.skipped_blocks or {}) do
      total = total + sk.len_block
      local bt = Pcapng.BlockType(sk.block_type)
      blocks[#blocks + 1] = bt and bt.label or string.format("0x%08x", sk.block_type)
    end
  end

  return {
    file_size = total,
    sections = sections,
    blocks = blocks,
    interfaces = interfaces,
    packets = packets,
    name_records = names,
    interface_stats = stats,
  }, packet_data
end

-- Parse one packet with link_frame and pick out the fields the golden files
-- hold, plus ether_type_name (nil when the ether type isn't in ether_type_enum;
-- then ether_type is nil too, since Lua loses an unknown enum's number).
function M.link_fields(link_type, data)
  local frame = LinkFrame(link_type, KaitaiStream(stringstream(data)))
  local body = frame.body
  if link_type == 1 then
    local et = body.ether_type
    return { ether_type = et and et.value, ether_type_name = et and et.label }
  elseif link_type == 113 then
    return { protocol = body.protocol }
  elseif link_type == 105 then
    return { wlan_type = body.frame_type and body.frame_type.value, wlan_subtype = body.subtype }
  elseif link_type == 127 then
    local w = body.frame
    return { wlan_type = w.frame_type and w.frame_type.value, wlan_subtype = w.subtype, radiotap_length = body.length }
  end
  return {}
end

return M
