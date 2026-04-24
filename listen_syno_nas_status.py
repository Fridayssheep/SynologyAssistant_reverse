#!/usr/bin/env python3
"""
Live Synology Assistant UDP monitor.

What it does:
- binds UDP on 9999, with fallback to 9998/9997
- optionally sends one or more broadcast probe packets to 255.255.255.255:9999
- parses clear-text SYNO packets with parse_syno_udp.py
- tracks NAS status transitions from BResponse/JResponse field 0xA7

Notes:
- Response-side parsing is based on confirmed reverse engineering.
- Probe packet types are still partly inferred, so the sender is configurable.
"""

from __future__ import annotations

import argparse
import json
import re
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Iterable

from parse_syno_udp import CLEAR_HEADER, PACKET_TYPE_NAMES, parse_packet


DEFAULT_LISTEN_PORTS = (9999, 9998, 9997)
DEFAULT_SEND_PORT = 9999
DEFAULT_SEND_BIND_PORT = 1234
DEFAULT_PACKET_TYPES = (0x0F, 0x01)
DEFAULT_A4 = 0x01020000
DEFAULT_A6 = 0x00000078
STATUS_PACKET_TYPES = {0x02, 0x06}
SERIAL_RE = re.compile(r"^[A-Z0-9]{8,20}$")


@dataclass
class DeviceState:
    key: str
    src_ip: str
    display_ip: str
    ip: str | None
    remote_ip: str | None
    mac: str | None
    name: str | None
    model: str | None
    platform: str | None
    serial: str | None
    packet_type: int | None
    packet_name: str | None
    status_value: int | None
    status_name: str | None
    conf: int | None
    con: int | None
    last_seen: float


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def build_u32_field(field_id: int, value: int) -> bytes:
    return bytes((field_id, 4)) + struct.pack("<I", value)


def build_probe_packet(packet_type: int, a4: int, a6: int) -> bytes:
    payload = b"".join(
        (
            build_u32_field(0xA4, a4),
            build_u32_field(0xA6, a6),
            build_u32_field(0x01, packet_type),
        )
    )
    return CLEAR_HEADER + payload


def parse_int_list(text: str) -> list[int]:
    values: list[int] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        values.append(int(chunk, 0))
    return values


def bind_listener(ports: Iterable[int]) -> tuple[socket.socket, int]:
    last_error: OSError | None = None
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            sock.setblocking(False)
            return sock, port
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is None:
        raise RuntimeError("no listen ports configured")
    raise last_error


def make_sender(bind_port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", bind_port))
    except OSError:
        sock.bind(("0.0.0.0", 0))
    return sock


def fields_by_id(parsed: dict[str, object]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for item in parsed.get("fields", []):
        field_id = item.get("field_id")
        if isinstance(field_id, str) and field_id not in result:
            result[field_id] = item
    return result


def first_text(fields: dict[str, dict[str, object]], *ids: str) -> str | None:
    for field_id in ids:
        item = fields.get(field_id)
        if item is None:
            continue
        value = item.get("value")
        if isinstance(value, str) and value:
            return value
    return None


def first_int(fields: dict[str, dict[str, object]], *ids: str) -> int | None:
    for field_id in ids:
        item = fields.get(field_id)
        if item is None:
            continue
        value = item.get("value")
        if isinstance(value, int):
            return value
    return None


def string_fields(fields: dict[str, dict[str, object]]) -> dict[str, str]:
    values: dict[str, str] = {}
    for field_id, item in fields.items():
        value = item.get("value")
        if isinstance(value, str) and value:
            values[field_id] = value
    return values


def looks_like_mac(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", value))


def looks_like_serial(value: str) -> bool:
    if not SERIAL_RE.fullmatch(value):
        return False
    if looks_like_mac(value):
        return False
    if value.isdigit():
        return False
    return any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value)


def choose_serial(fields: dict[str, dict[str, object]], name: str | None, model: str | None, mac: str | None) -> str | None:
    preferred_ids = ("0xc0", "0x78", "0x7f", "0x70", "0xa2", "0x56", "0x57", "0x58", "0x59", "0x5a", "0x5b", "0xc9")
    ignored = {value for value in (name, model, mac) if value}
    for field_id in preferred_ids:
        item = fields.get(field_id)
        value = item.get("value") if item else None
        if isinstance(value, str) and value not in ignored and looks_like_serial(value):
            return value
    for value in string_fields(fields).values():
        if value not in ignored and looks_like_serial(value):
            return value
    return None


def is_placeholder_ip(value: str | None) -> bool:
    return value in {None, "", "0.0.0.0", "1.0.0.0", "0.0.0.1"}


def choose_display_ip(src_ip: str, ip: str | None, remote_ip: str | None) -> str:
    for candidate in (ip, remote_ip):
        if candidate and candidate == src_ip:
            return candidate
    for candidate in (ip, remote_ip):
        if not is_placeholder_ip(candidate):
            return candidate
    return src_ip


def device_from_packet(parsed: dict[str, object], src_ip: str) -> DeviceState | None:
    packet_type = parsed.get("packet_type_value")
    if not isinstance(packet_type, int) or packet_type not in STATUS_PACKET_TYPES:
        return None

    fields = fields_by_id(parsed)
    status_item = fields.get("0xa7")
    status_value = status_item.get("value") if status_item else None
    status_name = status_item.get("decoded") if status_item else None
    if not isinstance(status_value, int):
        status_value = None
    if not isinstance(status_name, str):
        status_name = None

    ip = first_text(fields, "0x48")
    remote_ip = first_text(fields, "0x18")
    mac = first_text(fields, "0x7c", "0x21", "0x19")
    name = first_text(fields, "0x21", "0x11", "0x52", "0x53", "0x50", "0x51")
    model = first_text(fields, "0x78", "0xa2", "0x50", "0x51")
    platform = first_text(fields, "0x70")
    serial = choose_serial(fields, name=name, model=model, mac=mac)
    conf = first_int(fields, "0x71")
    con = first_int(fields, "0x76")

    display_ip = choose_display_ip(src_ip=src_ip, ip=ip, remote_ip=remote_ip)
    key = mac or display_ip or src_ip
    return DeviceState(
        key=key,
        src_ip=src_ip,
        display_ip=display_ip,
        ip=ip,
        remote_ip=remote_ip,
        mac=mac,
        name=name,
        model=model,
        platform=platform,
        serial=serial,
        packet_type=packet_type,
        packet_name=PACKET_TYPE_NAMES.get(packet_type),
        status_value=status_value,
        status_name=status_name,
        conf=conf,
        con=con,
        last_seen=time.time(),
    )


def state_changed(old: DeviceState | None, new: DeviceState) -> bool:
    if old is None:
        return True
    return (
        old.status_value != new.status_value
        or old.src_ip != new.src_ip
        or old.display_ip != new.display_ip
        or old.ip != new.ip
        or old.remote_ip != new.remote_ip
        or old.mac != new.mac
        or old.name != new.name
        or old.model != new.model
        or old.platform != new.platform
        or old.serial != new.serial
        or old.conf != new.conf
        or old.con != new.con
    )


def format_state(state: DeviceState) -> str:
    parts = [
        f"time={now_text()}",
        f"key={state.key}",
        f"packet={state.packet_name or state.packet_type}",
        f"status={state.status_name or state.status_value}",
        f"ip={state.display_ip}",
    ]
    if state.status_value is not None and state.status_name is not None:
        parts.append(f"status_value={state.status_value}")
    if state.src_ip != state.display_ip:
        parts.append(f"src_ip={state.src_ip}")
    if state.ip and state.ip != state.display_ip:
        parts.append(f"field_ip={state.ip}")
    if state.remote_ip:
        parts.append(f"field_remote_ip={state.remote_ip}")
    if state.mac:
        parts.append(f"mac={state.mac}")
    if state.name:
        parts.append(f"name={state.name}")
    if state.model:
        parts.append(f"model={state.model}")
    if state.platform:
        parts.append(f"platform={state.platform}")
    if state.serial:
        parts.append(f"serial={state.serial}")
    if state.conf is not None:
        parts.append(f"conf={state.conf}")
    if state.con is not None:
        parts.append(f"con={state.con}")
    return " ".join(parts)


def send_probes(
    sock: socket.socket,
    packet_types: Iterable[int],
    rounds: int,
    interval: float,
    a4: int,
    a6: int,
    target_ip: str,
    target_port: int,
    verbose: bool,
) -> None:
    for round_index in range(rounds):
        for packet_type in packet_types:
            blob = build_probe_packet(packet_type=packet_type, a4=a4, a6=a6)
            sock.sendto(blob, (target_ip, target_port))
            if verbose:
                print(
                    f"{now_text()} sent_probe "
                    f"packet_type=0x{packet_type:02x} "
                    f"target={target_ip}:{target_port} "
                    f"bytes={len(blob)}"
                )
        if round_index + 1 != rounds:
            time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Listen for Synology Assistant UDP NAS status packets.")
    parser.add_argument("--listen-ports", default="9999,9998,9997", help="ports to try for receiving")
    parser.add_argument("--target-ip", default="255.255.255.255", help="probe target ip")
    parser.add_argument("--target-port", type=int, default=DEFAULT_SEND_PORT, help="probe target port")
    parser.add_argument("--bind-send-port", type=int, default=DEFAULT_SEND_BIND_PORT, help="preferred local source port for probes")
    parser.add_argument("--packet-types", default="0x0f,0x01", help="comma-separated probe packet types")
    parser.add_argument("--a4", type=lambda s: int(s, 0), default=DEFAULT_A4, help="field 0xA4 u32 value")
    parser.add_argument("--a6", type=lambda s: int(s, 0), default=DEFAULT_A6, help="field 0xA6 u32 value")
    parser.add_argument("--rounds", type=int, default=3, help="probe rounds")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between probe rounds")
    parser.add_argument("--timeout", type=float, default=0.5, help="receive poll timeout")
    parser.add_argument("--duration", type=float, default=0.0, help="stop after N seconds, 0 means run forever")
    parser.add_argument("--no-probe", action="store_true", help="listen only, do not send probes")
    parser.add_argument("--print-all", action="store_true", help="print every status packet, not only changes")
    parser.add_argument("--dump-json", action="store_true", help="dump parsed packet json for every packet")
    parser.add_argument("--dump-strings", action="store_true", help="dump all parsed string fields for every packet")
    parser.add_argument("--verbose", action="store_true", help="print probe and non-status packet info")
    args = parser.parse_args()

    listen_ports = parse_int_list(args.listen_ports)
    packet_types = parse_int_list(args.packet_types)

    listener, listen_port = bind_listener(listen_ports)
    sender = make_sender(args.bind_send_port)
    devices: dict[str, DeviceState] = {}

    print(
        f"{now_text()} listening "
        f"local_port={listen_port} "
        f"probe={'off' if args.no_probe else 'on'} "
        f"packet_types={[hex(x) for x in packet_types]}"
    )

    if not args.no_probe:
        send_probes(
            sock=sender,
            packet_types=packet_types,
            rounds=args.rounds,
            interval=args.interval,
            a4=args.a4,
            a6=args.a6,
            target_ip=args.target_ip,
            target_port=args.target_port,
            verbose=args.verbose,
        )

    start = time.time()
    try:
        while True:
            if args.duration > 0 and time.time() - start >= args.duration:
                break

            ready, _, _ = select.select([listener], [], [], args.timeout)
            if not ready:
                continue

            blob, addr = listener.recvfrom(65535)
            try:
                parsed = parse_packet(blob)
            except Exception as exc:
                if args.verbose:
                    print(f"{now_text()} parse_error src={addr[0]}:{addr[1]} error={exc}")
                continue

            if args.dump_json:
                print(json.dumps({"src": f"{addr[0]}:{addr[1]}", "parsed": parsed}, ensure_ascii=False))
            if args.dump_strings:
                strings = string_fields(fields_by_id(parsed))
                if strings:
                    print(json.dumps({"src": f"{addr[0]}:{addr[1]}", "strings": strings}, ensure_ascii=False))

            state = device_from_packet(parsed, src_ip=addr[0])
            if state is None:
                if args.verbose:
                    packet_name = parsed.get("packet_type_name")
                    packet_value = parsed.get("packet_type_value")
                    print(
                        f"{now_text()} non_status_packet "
                        f"src={addr[0]}:{addr[1]} "
                        f"packet={packet_name or packet_value}"
                    )
                continue

            previous = devices.get(state.key)
            devices[state.key] = state
            if args.print_all or state_changed(previous, state):
                print(format_state(state))
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
        sender.close()

    if devices:
        print(f"{now_text()} summary devices={len(devices)}")
        for key in sorted(devices):
            print(format_state(devices[key]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
