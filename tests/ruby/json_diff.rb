# Compares two JSON-like values (as JSON.parse returns them) and lists every
# difference with its path, for example `[2].ts_ns: expected "1" but was
# "1704110400050000000"`. Numbers compare by value; paths count from 0.

require "json"

module JsonDiff
  module_function

  # Round-trips a value through JSON text, so both sides have the same shape
  # (string keys, plain arrays and hashes).
  def normalize(value)
    JSON.parse(JSON.generate(value))
  end

  def differences(expected, actual, ignore: nil, ignore_extra_fields: false)
    diffs = []
    compare(expected, actual, "", ignore, ignore_extra_fields, diffs)
    diffs
  end

  def compare(e, a, path, ignore, ignore_extra, diffs)
    return if ignore&.call(path)

    where = path.empty? ? "$" : path
    if e.is_a?(Hash) && a.is_a?(Hash)
      e.each do |k, ev|
        p = path.empty? ? k : "#{path}.#{k}"
        if !a.key?(k)
          diffs << "#{p}: missing (expected #{ev.to_json})" unless ignore&.call(p)
        else
          compare(ev, a[k], p, ignore, ignore_extra, diffs)
        end
      end
      unless ignore_extra
        (a.keys - e.keys).each do |k|
          p = path.empty? ? k : "#{path}.#{k}"
          diffs << "#{p}: unexpected (was #{a[k].to_json})"
        end
      end
    elsif e.is_a?(Array) && a.is_a?(Array)
      diffs << "#{where}: expected #{e.size} items but was #{a.size}" if e.size != a.size
      [e.size, a.size].min.times do |i|
        compare(e[i], a[i], "#{path}[#{i}]", ignore, ignore_extra, diffs)
      end
    elsif e.is_a?(Numeric) && a.is_a?(Numeric)
      diffs << "#{where}: expected #{e.to_json} but was #{a.to_json}" if e != a
    elsif e != a || e.class != a.class
      diffs << "#{where}: expected #{e.to_json} but was #{a.to_json}"
    end
  end
end
