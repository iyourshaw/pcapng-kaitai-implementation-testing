<?php
declare(strict_types=1);

namespace PcapngTests;

use Kaitai\Struct\Stream;
use PcapngFormats\EthernetFrame;
use PcapngFormats\LinkFrame;
use PcapngFormats\Pcapng;
use PcapngFormats\Pcapng\BlockType;

/**
 * Turns a parsed Pcapng into the shape of tests/expected/<sample>.json.
 * Only the generated code reads the file; this reads the parsed object tree.
 *
 * PHP enums are plain ints, so an unknown value keeps its number, and names come
 * from the generated constants. Timestamps use bcmath, since ts * 1e9 can pass
 * PHP_INT_MAX.
 */
final class PcapngSummary
{
    private const BOM_LE = "\x4d\x3c\x2b\x1a";
    private const ISB_COUNTERS = [4 => 'ifrecv', 5 => 'ifdrop', 6 => 'filteraccept', 7 => 'osdrop', 8 => 'usrdeliv'];

    /** @var array<int, string>|null block_type value => .ksy name */
    private static ?array $blockTypeNames = null;

    public static function blockTypeName(int $value): string
    {
        if (self::$blockTypeNames === null) {
            self::$blockTypeNames = [];
            foreach ((new \ReflectionClass(BlockType::class))->getConstants() as $name => $v) {
                if (is_int($v)) {
                    self::$blockTypeNames[$v] = strtolower($name);
                }
            }
        }
        return self::$blockTypeNames[$value] ?? sprintf('0x%08x', $value);
    }

    /** A timestamp in nanoseconds (a decimal string), from if_tsresol and if_tsoffset. */
    public static function tsNs(int $tsHigh, int $tsLow, int $tsresol, int $tsoffset): string
    {
        $ts = bcadd(bcmul((string) $tsHigh, '4294967296'), (string) $tsLow);
        $scaled = bcmul($ts, '1000000000');
        $div = ($tsresol & 0x80) ? bcpow('2', (string) ($tsresol & 0x7f)) : bcpow('10', (string) $tsresol);
        $ns = bcdiv($scaled, $div, 0);  // scale 0: truncates, which is floor for non-negative values
        return bcadd($ns, bcmul((string) $tsoffset, '1000000000'));
    }

    /** @return list<object> */
    private static function entries(?object $options): array
    {
        return $options?->entries() ?? [];
    }

    private static function firstText(?object $options, int $code): ?string
    {
        foreach (self::entries($options) as $o) {
            if ($o->code() === $code) {
                return $o->value()->value();
            }
        }
        return null;
    }

    /** @return list<string> */
    private static function comments(?object $options): array
    {
        $out = [];
        foreach (self::entries($options) as $o) {
            if ($o->code() === 1) {
                $out[] = $o->value()->value();
            }
        }
        return $out;
    }

    private static function packet(int $si, array $iface, int $interfaceId, int $capLen, int $origLen,
                                   int $tsHigh, int $tsLow, ?object $options): array
    {
        return [
            'section' => $si,
            'interface_id' => $interfaceId,
            'cap_len' => $capLen,
            'orig_len' => $origLen,
            'ts_ns' => self::tsNs($tsHigh, $tsLow, $iface['tsresol'], $iface['tsoffset']),
            'comments' => self::comments($options),
        ];
    }

    /**
     * @return array{0: array<string, mixed>, 1: list<array{0: ?int, 1: string}>}
     *         the summary, and [link type, bytes] for every packet
     */
    public static function summarize(Pcapng $parsed): array
    {
        $sections = $blocks = $interfaces = $packets = $names = $stats = [];
        $ifaces = [];
        $packetData = [];
        $total = 0;

        foreach ($parsed->sections() as $si => $sif) {
            $sec = $sif->section();
            $shb = $sec->header()->body();
            $sections[] = [
                'endian' => $sif->byteOrderMagic() === self::BOM_LE ? 'le' : 'be',
                'version' => [$shb->versionMajor(), $shb->versionMinor()],
                'section_length' => $shb->sectionLength(),
                'hardware' => self::firstText($shb->options(), 2),
                'os' => self::firstText($shb->options(), 3),
                'userappl' => self::firstText($shb->options(), 4),
                'comments' => self::comments($shb->options()),
            ];
            $firstIface = count($ifaces);

            $all = array_merge([$sec->header()], $sec->blocks() ?? []);
            foreach ($all as $b) {
                $total += $b->lenBlock();
                $blocks[] = self::blockTypeName($b->blockType());
                $body = $b->body();
                switch ($b->blockType()) {
                    case BlockType::INTERFACE_DESCRIPTION:
                        $tsresol = $tsoffset = null;
                        foreach (self::entries($body->options()) as $o) {
                            if ($o->code() === 9 && $tsresol === null) $tsresol = $o->value()->value();
                            if ($o->code() === 14 && $tsoffset === null) $tsoffset = $o->value()->value();
                        }
                        $iface = [
                            'link_type' => $body->linkType(),
                            'snaplen' => $body->snaplen(),
                            'tsresol' => $tsresol ?? 6,
                            'tsoffset' => $tsoffset ?? 0,
                        ];
                        $ifaces[] = $iface;
                        $interfaces[] = [
                            'section' => $si,
                            'link_type' => $iface['link_type'],
                            'snaplen' => $body->snaplen(),
                            'name' => self::firstText($body->options(), 2),
                            'description' => self::firstText($body->options(), 3),
                            'tsresol' => $iface['tsresol'],
                            'tsoffset' => $iface['tsoffset'],
                            'comments' => self::comments($body->options()),
                        ];
                        break;
                    case BlockType::ENHANCED_PACKET:
                    case BlockType::PACKET:
                        $iface = $ifaces[$firstIface + $body->interfaceId()];
                        $packets[] = self::packet($si, $iface, $body->interfaceId(), $body->lenPacketData(),
                            $body->lenOriginal(), $body->tsHigh(), $body->tsLow(), $body->options());
                        $packetData[] = [$iface['link_type'], $body->packetData()];
                        break;
                    case BlockType::SIMPLE_PACKET:
                        $iface = $ifaces[$firstIface];
                        $bytes = $body->packetDataAndPadding();
                        $cap = min($body->lenOriginal(), strlen($bytes));
                        if ($iface['snaplen'] !== 0) $cap = min($cap, $iface['snaplen']);
                        $packets[] = [
                            'section' => $si, 'interface_id' => 0, 'cap_len' => $cap,
                            'orig_len' => $body->lenOriginal(), 'ts_ns' => null, 'comments' => [],
                        ];
                        $packetData[] = [$iface['link_type'], substr($bytes, 0, $cap)];
                        break;
                    case BlockType::NAME_RESOLUTION:
                        foreach ($body->records() as $rec) {
                            if ($rec->recordType() === 0) continue;
                            if ($rec->recordType() >= 1 && $rec->recordType() <= 4) {
                                $names[] = [
                                    'record_type' => $rec->recordType(),
                                    'address' => bin2hex($rec->value()->address()),
                                    'names' => array_values(array_filter($rec->value()->names(), fn($n) => $n !== '')),
                                ];
                            } else {
                                $names[] = ['record_type' => $rec->recordType(), 'value' => bin2hex($rec->value())];
                            }
                        }
                        break;
                    case BlockType::INTERFACE_STATISTICS:
                        $st = ['section' => $si, 'interface_id' => $body->interfaceId(),
                               'ts_high' => $body->tsHigh(), 'ts_low' => $body->tsLow()];
                        foreach (self::entries($body->options()) as $o) {
                            $code = $o->code();
                            if (($code === 2 || $code === 3) && $o->value()->tsHigh() !== null) {
                                $st[$code === 2 ? 'starttime' : 'endtime'] = [$o->value()->tsHigh(), $o->value()->tsLow()];
                            } elseif (isset(self::ISB_COUNTERS[$code]) && $o->value()->value() !== null) {
                                $st[self::ISB_COUNTERS[$code]] = $o->value()->value();
                            } elseif ($code === 1) {
                                $st['comments'][] = $o->value()->value();
                            }
                        }
                        $stats[] = $st;
                        break;
                }
            }
            foreach ($sec->skippedBlocks() ?? [] as $sk) {
                $total += $sk->lenBlock();
                $blocks[] = self::blockTypeName($sk->blockType());
            }
        }

        return [[
            'file_size' => $total,
            'sections' => $sections,
            'blocks' => $blocks,
            'interfaces' => $interfaces,
            'packets' => $packets,
            'name_records' => $names,
            'interface_stats' => $stats,
        ], $packetData];
    }

    /**
     * Parse one packet with link_frame and pick out the fields the golden files
     * hold, plus ether_type_name (null when the ether type isn't in ether_type_enum).
     */
    public static function linkFields(int $linkType, string $data): array
    {
        $frame = new LinkFrame($linkType, new Stream($data));
        $body = $frame->body();
        return match ($linkType) {
            1 => [
                'ether_type' => $body->etherType(),
                'ether_type_name' => EthernetFrame\EtherTypeEnum::isDefined($body->etherType()) ? 'named' : null,
            ],
            113 => ['protocol' => $body->protocol()],
            105 => ['wlan_type' => $body->frameType(), 'wlan_subtype' => $body->subtype()],
            127 => [
                'wlan_type' => $body->frame()->frameType(),
                'wlan_subtype' => $body->frame()->subtype(),
                'radiotap_length' => $body->length(),
            ],
            default => [],
        };
    }
}
