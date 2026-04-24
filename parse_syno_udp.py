#!/usr/bin/env python3
"""
Minimal Synology Assistant UDP payload parser.

What it does:
- validates the 8-byte SYNO header
- parses ordinary TLV fields
- annotates confirmed field IDs from the Linux Assistant binary
- decodes IPv4 fields that are stored as network-order u32
- keeps special/array fields as opaque payloads

This is intentionally conservative: it only marks semantics that were
confirmed from the binary, and leaves the rest as unknown_* placeholders.
"""

from __future__ import annotations

import argparse
import binascii
import ipaddress
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


CLEAR_HEADER = bytes.fromhex("12 34 56 78 53 59 4E 4F")
ALT_HEADER = bytes.fromhex("12 34 55 66 53 59 4E 4F")

PACKET_TYPE_NAMES: dict[int, str] = {
    0x01: "discovery_request_plain_inferred",
    0x02: "BResponse",
    0x03: "NSET",
    0x04: "QCF",
    0x06: "JResponse",
    0x12: "response_type_0x12",
    0x13: "request_type_0x13_control_or_keyed_request_inferred",
}

REQUEST_CLASS_PACKET_TYPES = {0x01, 0x13}
DISCOVERY_CORE_FIELDS = {0x01, 0xA4, 0xA6}
KEY_MATERIAL_FIELDS = {0xC4, 0xC5}
KEY_RANGE_FIELDS = {0xB0, 0xB1, 0xB8, 0xB9}
CONTROL_HEAVY_FIELDS = {0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x2A, 0x4A, 0xC2}

STATUS_ENUM: dict[int, str] = {
    0: "IDS_LST_SYS_UNCONFIG",
    1: "IDS_LST_SYS_READY",
    2: "IDS_LST_SYS_UNINSTALL",
    3: "IDS_LST_SYS_UPDATING",
    4: "IDS_LST_SYS_CRASH",
    5: "IDS_LST_SYS_BOOTING",
    6: "IDS_LST_SYS_QUOTA_CHECKING",
    7: "IDS_LST_SYS_SERVICE_STARTING",
    8: "IDS_LST_SYS_NET_ERROR",
    10: "IDS_LST_SYS_NET_TESTING",
    11: "IDS_LST_SYS_RECOVERABLE",
    12: "IDS_WAKEUP_OFF_LINE",
    13: "IDS_LST_SYS_CHECKING_PROGRESS",
    14: "IDS_LST_SYS_MIGRAT",
}


@dataclass(frozen=True)
class FieldInfo:
    kind: str
    struct_offset: int
    size: int
    name: str


# Confirmed from the static field descriptor table around .data:0x89f160.
FIELD_MAP: dict[int, FieldInfo] = {
    0x01: FieldInfo("u32", 0x0ED0, 4, "packet_type"),
    0x11: FieldInfo("str", 0x0008, 0x24, "string_0x11"),
    0x12: FieldInfo("u32", 0x0E90, 4, "u32_0x12"),
    0x13: FieldInfo("u32", 0x0E94, 4, "u32_0x13"),
    0x14: FieldInfo("u32", 0x0E98, 4, "u32_0x14"),
    0x15: FieldInfo("u32", 0x0E9C, 4, "u32_0x15"),
    0x18: FieldInfo("ipv4", 0x0EA0, 4, "remote_ip"),
    0x19: FieldInfo("str", 0x002C, 0x24, "string_0x19"),
    0x1A: FieldInfo("str", 0x0074, 0x604, "long_string_0x1a"),
    0x1E: FieldInfo("u32", 0x0EA8, 4, "u32_0x1e"),
    0x1F: FieldInfo("u32", 0x0EA4, 4, "u32_0x1f"),
    0x20: FieldInfo("u32", 0x0E8C, 4, "u32_0x20"),
    0x21: FieldInfo("str", 0x0008, 0x24, "string_0x21"),
    0x22: FieldInfo("u32", 0x0E90, 4, "u32_0x22"),
    0x23: FieldInfo("u32", 0x0E94, 4, "u32_0x23"),
    0x24: FieldInfo("u32", 0x0E98, 4, "u32_0x24"),
    0x25: FieldInfo("u32", 0x0E9C, 4, "u32_0x25"),
    0x29: FieldInfo("str", 0x002C, 0x24, "string_0x29"),
    0x2A: FieldInfo("str", 0x0074, 0x604, "long_string_0x2a"),
    0x48: FieldInfo("ipv4", 0x0EB8, 4, "ip"),
    0x49: FieldInfo("ipv4", 0x0EBC, 4, "ipv4_0x49"),
    0x4A: FieldInfo("str", 0x0C24, 0x1F0, "string_0x4a"),
    0x4D: FieldInfo("u32", 0x0F08, 4, "u32_0x4d"),
    0x50: FieldInfo("str", 0x0678, 0x14, "string_0x50"),
    0x51: FieldInfo("str", 0x068C, 0x14, "string_0x51"),
    0x52: FieldInfo("str", 0x06A0, 0x104, "string_0x52"),
    0x53: FieldInfo("str", 0x07A4, 0x104, "string_0x53"),
    0x54: FieldInfo("u32", 0x0E84, 4, "u32_0x54"),
    0x55: FieldInfo("u32", 0x0E88, 4, "u32_0x55"),
    0x56: FieldInfo("str", 0x08A8, 0x80, "string_0x56"),
    0x57: FieldInfo("str", 0x0928, 0x80, "string_0x57"),
    0x58: FieldInfo("str", 0x09A8, 0x80, "string_0x58"),
    0x59: FieldInfo("str", 0x0A28, 0x80, "string_0x59"),
    0x5A: FieldInfo("str", 0x0AA8, 0x80, "string_0x5a"),
    0x5B: FieldInfo("str", 0x0B28, 0x80, "string_0x5b"),
    0x5C: FieldInfo("str", 0x0BA8, 4, "blob_0x5c"),
    0x5D: FieldInfo("str", 0x0BAC, 4, "blob_0x5d"),
    0x60: FieldInfo("u32", 0x0ED8, 4, "u32_0x60"),
    0x70: FieldInfo("str", 0x0BB0, 0x44, "string_0x70"),
    0x71: FieldInfo("u32", 0x0EC4, 4, "conf"),
    0x73: FieldInfo("str", 0x0BF4, 0x0C, "string_0x73"),
    0x75: FieldInfo("u32", 0x0EAC, 4, "u32_0x75"),
    0x76: FieldInfo("u32", 0x0EB0, 4, "con"),
    0x77: FieldInfo("str", 0x0E14, 8, "blob_0x77"),
    0x78: FieldInfo("str", 0x0E24, 0x30, "string_0x78"),
    0x79: FieldInfo("u32", 0x0EDC, 4, "u32_0x79"),
    0x7B: FieldInfo("u32", 0x0EE4, 4, "u32_0x7b"),
    0x7C: FieldInfo("str", 0x0050, 0x24, "string_0x7c"),
    0x7D: FieldInfo("u32", 0x0EC0, 4, "u32_0x7d"),
    0x7E: FieldInfo("str", 0x0E1C, 8, "blob_0x7e"),
    0x7F: FieldInfo("str", 0x0E54, 0x30, "string_0x7f"),
    0x80: FieldInfo("u32", 0x0EE0, 4, "u32_0x80"),
    0x8D: FieldInfo("u32", 0x2F9C, 4, "u32_0x8d"),
    0x8E: FieldInfo("u32", 0x2FA0, 4, "u32_0x8e"),
    0x8F: FieldInfo("u32", 0x2FA4, 4, "u32_0x8f"),
    0x90: FieldInfo("u32", 0x2F34, 4, "u32_0x90"),
    0xA2: FieldInfo("str", 0x0C00, 0x24, "string_0xa2"),
    0xA3: FieldInfo("u32", 0x0ECC, 4, "u32_0xa3"),
    0xA4: FieldInfo("u32", 0x0EC8, 4, "u32_0xa4"),
    0xA6: FieldInfo("u32", 0x0ED4, 4, "u32_0xa6"),
    0xA7: FieldInfo("u32", 0x0EB4, 4, "status_or_err"),
    0xB0: FieldInfo("u64", 0x0EE8, 8, "u64_0xb0"),
    0xB1: FieldInfo("u64", 0x0EF0, 8, "u64_0xb1"),
    0xB8: FieldInfo("u64", 0x0EF8, 8, "u64_0xb8"),
    0xB9: FieldInfo("u64", 0x0F00, 8, "u64_0xb9"),
    0xBA: FieldInfo("u32", 0x0F0C, 4, "u32_0xba"),
    0xBB: FieldInfo("u32", 0x0F10, 4, "u32_0xbb"),
    0xBC: FieldInfo("array", 0x0F14, 0x40, "array_0xbc"),
    0xBD: FieldInfo("array", 0x1714, 0x40, "array_0xbd"),
    0xBE: FieldInfo("array", 0x1F14, 0x40, "array_0xbe"),
    0xBF: FieldInfo("array", 0x2714, 0x40, "array_0xbf"),
    0xC0: FieldInfo("str", 0x2F14, 0x20, "string_0xc0"),
    0xC1: FieldInfo("str", 0x2F38, 8, "blob_0xc1"),
    0xC2: FieldInfo("u32", 0x2F40, 4, "u32_0xc2"),
    0xC3: FieldInfo("u32", 0x2F44, 4, "u32_0xc3"),
    0xC4: FieldInfo("str", 0x2F48, 0x41, "string_0xc4"),
    0xC5: FieldInfo("u32", 0x2F8C, 4, "u32_0xc5"),
    0xC6: FieldInfo("u32", 0x2F90, 4, "u32_0xc6"),
    0xC7: FieldInfo("u32", 0x2F94, 4, "u32_0xc7"),
    0xC8: FieldInfo("u32", 0x2F98, 4, "u32_0xc8"),
    0xC9: FieldInfo("str", 0x2FA8, 0x24, "string_0xc9"),
}


def decode_value(field_id: int, payload: bytes) -> object:
    info = FIELD_MAP.get(field_id)
    if not info:
        return payload.hex()

    if info.kind == "ipv4" and len(payload) == 4:
        return str(ipaddress.IPv4Address(struct.unpack(">I", payload)[0]))
    if info.kind == "u32" and len(payload) == 4:
        return struct.unpack("<I", payload)[0]
    if info.kind == "u64" and len(payload) == 8:
        return struct.unpack("<Q", payload)[0]
    if info.kind == "str":
        try:
            return payload.split(b"\x00", 1)[0].decode("utf-8")
        except UnicodeDecodeError:
            return payload.hex()
    return payload.hex()


def parse_packet(blob: bytes) -> dict[str, object]:
    if len(blob) < 8:
        raise ValueError("packet too short")

    header = blob[:8]
    if header == CLEAR_HEADER:
        header_kind = "clear"
    elif header == ALT_HEADER:
        header_kind = "alt_or_encrypted"
    else:
        raise ValueError(f"unknown header: {header.hex()}")

    items: list[dict[str, object]] = []
    long_chunks: list[bytes] = []
    field_ids: set[int] = set()
    pos = 8

    while pos < len(blob):
        field_id = blob[pos]
        field_ids.add(field_id)
        pos += 1

        if field_id in (0x72, 0xA0, 0xA1):
            # Binary confirmed these IDs use dedicated parsing branches.
            if pos >= len(blob):
                break
            length = blob[pos]
            pos += 1
            payload = blob[pos : pos + length]
            pos += len(payload)
            if field_id == 0x72:
                long_chunks.append(payload)
            items.append(
                {
                    "field_id": f"0x{field_id:02x}",
                    "name": {
                        0x72: "special_long_chunk_0x72",
                        0xA0: "special_extension_0xa0",
                        0xA1: "special_extension_0xa1",
                    }.get(field_id, f"special_0x{field_id:02x}"),
                    "special": True,
                    "raw": payload.hex(),
                }
            )
            continue

        if pos >= len(blob):
            items.append(
                {
                    "field_id": f"0x{field_id:02x}",
                    "error": "missing length byte",
                }
            )
            break

        length = blob[pos]
        pos += 1
        payload = blob[pos : pos + length]
        pos += len(payload)

        info = FIELD_MAP.get(field_id)
        items.append(
            {
                "field_id": f"0x{field_id:02x}",
                "name": info.name if info else f"unknown_0x{field_id:02x}",
                "struct_offset": f"0x{info.struct_offset:x}" if info else None,
                "declared_kind": info.kind if info else None,
                "length": length,
                "value": decode_value(field_id, payload),
                "raw": payload.hex(),
            }
        )

    packet_type_value = None
    for item in items:
        if item.get("field_id") == "0x01" and isinstance(item.get("value"), int):
            packet_type_value = item["value"]
            item["decoded"] = PACKET_TYPE_NAMES.get(packet_type_value, "unknown_packet_type")

    for item in items:
        if item.get("field_id") != "0xa7" or not isinstance(item.get("value"), int):
            continue
        if packet_type_value in (0x02, 0x06):
            item["role"] = "system_status"
            item["decoded"] = STATUS_ENUM.get(item["value"], "reserved_or_unmapped_status")
        elif packet_type_value in (0x03, 0x04):
            item["role"] = "error_code"
        else:
            item["role"] = "status_or_err"

    result: dict[str, object] = {
        "header_kind": header_kind,
        "header_hex": header.hex(),
        "packet_type_value": packet_type_value,
        "packet_type_name": PACKET_TYPE_NAMES.get(packet_type_value) if packet_type_value is not None else None,
        "field_count": len(items),
        "fields": items,
    }
    if packet_type_value in REQUEST_CLASS_PACKET_TYPES:
        result["request_class"] = True
    if DISCOVERY_CORE_FIELDS.issubset(field_ids):
        result["has_discovery_core_fields"] = True
    if field_ids & KEY_MATERIAL_FIELDS:
        result["has_key_material_fields"] = sorted(f"0x{x:02x}" for x in field_ids & KEY_MATERIAL_FIELDS)
    if field_ids & KEY_RANGE_FIELDS:
        result["has_key_range_fields"] = sorted(f"0x{x:02x}" for x in field_ids & KEY_RANGE_FIELDS)
    if field_ids & CONTROL_HEAVY_FIELDS:
        result["has_control_heavy_fields"] = sorted(f"0x{x:02x}" for x in field_ids & CONTROL_HEAVY_FIELDS)
    if packet_type_value == 0x01 and DISCOVERY_CORE_FIELDS.issubset(field_ids) and not (field_ids & CONTROL_HEAVY_FIELDS):
        result["request_profile"] = "minimal_or_near-minimal_discovery_candidate"
    elif packet_type_value == 0x13:
        result["request_profile"] = "control_or_keyed_request_candidate"
    if field_ids & {0xA0, 0xA1}:
        result["has_special_extension_fields"] = sorted(f"0x{x:02x}" for x in field_ids & {0xA0, 0xA1})
    if long_chunks:
        try:
            result["field_0x72_reassembled"] = b"".join(long_chunks).decode("utf-8")
        except UnicodeDecodeError:
            result["field_0x72_reassembled"] = b"".join(long_chunks).hex()
    return result


def read_input(args: argparse.Namespace) -> bytes:
    if args.hex:
        compact = "".join(args.hex.split())
        return binascii.unhexlify(compact)
    if args.file:
        return Path(args.file).read_bytes()
    raw = sys.stdin.buffer.read()
    if not raw:
        raise ValueError("no input data")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Synology Assistant UDP payloads.")
    parser.add_argument("--hex", help="packet bytes as hex")
    parser.add_argument("--file", help="read packet bytes from a file")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    args = parser.parse_args()

    blob = read_input(args)
    result = parse_packet(blob)
    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
