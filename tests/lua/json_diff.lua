-- Compares two JSON-like Lua values and lists every difference with its path,
-- for example `[3].ts_ns: expected "1" but was "1704110400050000000"`.
-- JSON null is json.null (dkjson's sentinel) on both sides. Paths count array
-- items from 1, as Lua does.

local json = require("dkjson")

local M = {}

local function is_array(t)
  local mt = getmetatable(t)
  if mt and mt.__jsontype then
    return mt.__jsontype == "array"
  end
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n == #t
end

local function show(v)
  if v == nil then return "(missing)" end
  if v == json.null then return "null" end
  if type(v) == "string" then return string.format("%q", v) end
  if type(v) == "table" then return json.encode(v) end
  return tostring(v)
end

local function compare(e, a, path, opts, diffs)
  local where = path == "" and "$" or path
  if opts.ignore and opts.ignore(path) then return end
  if type(e) == "table" and e ~= json.null and type(a) == "table" and a ~= json.null then
    if is_array(e) then
      if not is_array(a) then
        diffs[#diffs + 1] = where .. ": expected an array but was " .. show(a)
        return
      end
      if #e ~= #a then
        diffs[#diffs + 1] = string.format("%s: expected %d items but was %d", where, #e, #a)
      end
      for i = 1, math.min(#e, #a) do
        compare(e[i], a[i], string.format("%s[%d]", path, i), opts, diffs)
      end
    else
      for k, ev in pairs(e) do
        local p = path == "" and k or (path .. "." .. k)
        if a[k] == nil then
          if not (opts.ignore and opts.ignore(p)) then
            diffs[#diffs + 1] = p .. ": missing (expected " .. show(ev) .. ")"
          end
        else
          compare(ev, a[k], p, opts, diffs)
        end
      end
      if not opts.ignore_extra_fields then
        for k, av in pairs(a) do
          if e[k] == nil then
            local p = path == "" and k or (path .. "." .. k)
            diffs[#diffs + 1] = p .. ": unexpected (was " .. show(av) .. ")"
          end
        end
      end
    end
  elseif e ~= a then
    diffs[#diffs + 1] = where .. ": expected " .. show(e) .. " but was " .. show(a)
  end
end

-- opts.ignore(path) -> true to skip a path; opts.ignore_extra_fields to allow
-- fields in `actual` that `expected` doesn't have.
function M.differences(expected, actual, opts)
  local diffs = {}
  compare(expected, actual, "", opts or {}, diffs)
  return diffs
end

return M
