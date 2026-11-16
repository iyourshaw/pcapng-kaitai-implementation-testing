<?php
declare(strict_types=1);

namespace PcapngTests;

/**
 * Compares two JSON-like values (decoded with json_decode(..., true)) and lists
 * every difference with its path, for example `[2].ts_ns: expected "1" but was
 * "1704110400050000000"`. Numbers compare by value; paths count from 0.
 */
final class JsonDiff
{
    /**
     * @param callable(string):bool|null $ignore           paths to skip
     * @param bool                       $ignoreExtraFields fields in $actual that $expected doesn't have are fine
     * @return list<string>
     */
    public static function differences(mixed $expected, mixed $actual, ?callable $ignore = null,
                                       bool $ignoreExtraFields = false): array
    {
        $diffs = [];
        self::compare($expected, $actual, '', $ignore, $ignoreExtraFields, $diffs);
        return $diffs;
    }

    /** Round-trips a value through JSON text, so both sides have the same shape. */
    public static function normalize(mixed $value): mixed
    {
        return json_decode(json_encode($value, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION), true, 512,
            JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
    }

    private static function compare(mixed $e, mixed $a, string $path, ?callable $ignore, bool $ignoreExtra,
                                    array &$diffs): void
    {
        if ($ignore !== null && $ignore($path)) {
            return;
        }
        $where = $path === '' ? '$' : $path;
        if (is_array($e) && is_array($a)) {
            if (array_is_list($e) && array_is_list($a)) {
                if (count($e) !== count($a)) {
                    $diffs[] = sprintf('%s: expected %d items but was %d', $where, count($e), count($a));
                }
                for ($i = 0; $i < min(count($e), count($a)); $i++) {
                    self::compare($e[$i], $a[$i], "{$path}[{$i}]", $ignore, $ignoreExtra, $diffs);
                }
                return;
            }
            foreach ($e as $k => $ev) {
                $p = $path === '' ? (string) $k : "{$path}.{$k}";
                if (!array_key_exists($k, $a)) {
                    if ($ignore === null || !$ignore($p)) {
                        $diffs[] = "{$p}: missing (expected " . self::show($ev) . ')';
                    }
                    continue;
                }
                self::compare($ev, $a[$k], $p, $ignore, $ignoreExtra, $diffs);
            }
            if (!$ignoreExtra) {
                foreach ($a as $k => $av) {
                    if (!array_key_exists($k, $e)) {
                        $p = $path === '' ? (string) $k : "{$path}.{$k}";
                        $diffs[] = "{$p}: unexpected (was " . self::show($av) . ')';
                    }
                }
            }
            return;
        }
        $same = (is_int($e) || is_float($e)) && (is_int($a) || is_float($a)) ? $e == $a : $e === $a;
        if (!$same) {
            $diffs[] = "{$where}: expected " . self::show($e) . ' but was ' . self::show($a);
        }
    }

    private static function show(mixed $v): string
    {
        return json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
}
