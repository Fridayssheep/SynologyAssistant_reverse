#!/usr/bin/env python3
"""
Reverse-engineered Synology Assistant memory-test flow helper.

What this script does today:
- discovers a NAS over the Assistant UDP protocol
- prompts for the administrator account and password when needed
- reproduces the currently recovered password codec used on the memory-test path
- prints the currently confirmed reverse-engineered flow
- optionally waits for the NAS to enter memory-test state and reports progress

What it can do now:
- actively performs the Assistant key exchange (`0xc4` local public key +
  `0xc5` local key id), decrypts the NAS response with the local private key,
  and extracts the NAS public key needed by the memory-test sealed box
- builds and optionally sends the final "start memory test" control packet

Confirmed reverse-engineering evidence baked into this helper:
- `slotMemTestTrigged()`
- `slotDoMemTest`
- `Enter the Admin's Password`
- `Administrator account:`
- `Hint:`
- `0x45d4b0 -> 0x45b0c0 -> 0x47d010 -> 0x4abe80 -> 0x4ac900`
"""

from __future__ import annotations

import argparse
import getpass
import json
import math
import secrets
import select
import socket
import struct
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from listen_syno_nas_status import (
    DEFAULT_A4,
    DEFAULT_A6,
    DEFAULT_PACKET_TYPES,
    DEFAULT_SEND_BIND_PORT,
    DEFAULT_SEND_PORT,
    DeviceState,
    bind_listener,
    build_probe_packet,
    device_from_packet,
    format_state,
    make_sender,
)
from parse_syno_udp import ALT_HEADER, CLEAR_HEADER, parse_packet


DEFAULT_LISTEN_PORTS = (9999, 9998, 9997)
DEFAULT_DISCOVERY_TIMEOUT = 8.0
PASSWORD_ALPHABET = "UPX-BkYa4Fyi2DjcLef6WmOA8pZrshQ+uv7Vwx3G9oHb1EIJKzMg5NqRSCtTld0n"
PASSWORD_REVERSE_TABLE = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000001f000300003e2c0c26083413221828000000000000"
    "001704390d2d09272a2e2f3010323516011e37383b00231402061a0000000000"
    "00072b0f3d1112331d0b0e053c153f2919361b1c3a202124250a310000000000"
)
PASSWORD_FORWARD_MATRIX = (
    (0.0, 2.0, 2.0, -3.0, 0.0, 1.0, 3.0, -1.0),
    (1.0, 1.0, -2.0, 3.0, -1.0, 0.0, 0.0, 5.0),
    (-2.0, 1.0, 1.0, -1.0, 3.0, 0.0, -1.0, -2.0),
    (-1.0, 0.0, 0.0, 0.0, 2.0, -3.0, -4.0, 1.0),
    (0.0, -2.0, 1.0, 2.0, -2.0, 1.0, -2.0, -1.0),
    (-1.0, 2.0, 0.0, 2.0, -2.0, -2.0, 1.0, 0.0),
    (2.0, -4.0, 3.0, -2.0, 1.0, 5.0, 3.0, 1.0),
    (1.0, 0.0, -5.0, 0.0, -1.0, -2.0, -1.0, -3.0),
)
PASSWORD_INVERSE_MATRIX = (
    (2.27981, 1.83678, 1.61159, 2.1972, 1.60227, 2.13791, 2.26982, 2.18188),
    (0.952476, 0.749944, 0.667555, 0.620475, 0.624695, 0.562292, 0.549412, 0.669109),
    (0.834555, 0.568732, 0.566955, 0.851654, 0.628026, 0.882745, 0.828559, 0.642461),
    (0.768599, 0.857206, 0.951366, 0.862314, 0.714635, 1.21452, 1.08639, 0.949589),
    (0.67777, 0.715745, 0.881412, 0.833222, 0.436598, 0.934044, 0.986898, 0.840551),
    (-0.212303, -0.0983789, -0.0926049, -0.517877, -0.0410837, -0.618921, -0.442816, -0.337997),
    (-0.231401, -0.142794, -0.0486342, -0.137686, -0.285365, 0.214524, 0.0863869, -0.0504108),
    (-0.638241, -0.461026, -0.623584, -0.573618, -0.535643, -0.728847, -0.686875, -0.714857),
)
PASSWORD_DECODE_EPSILON = 0.01
MEMTEST_PACKET_TYPE = 0x0C
MEMTEST_FIELD_ORDER = (0xA4, 0xA6, 0x01, 0x19, 0x2A, 0x4A, 0xC2, 0xC5)
DEFAULT_MEMTEST_CONTROL_WORD = 0
KEY_EXCHANGE_PACKET_TYPE = 0x01
KEY_EXCHANGE_FIELD_ORDER = (0xA4, 0xA6, 0x01, 0xB0, 0xB1, 0xB8, 0xB9, 0x7C, 0xC4, 0xC5)
DEFAULT_KEY_EXCHANGE_RANGE = 0x1C0


def _add_vendored_pynacl() -> None:
    vendor = Path(__file__).resolve().parent / ".vendor" / "pynacl"
    if vendor.exists():
        sys.path.insert(0, str(vendor))


def require_nacl_bindings():
    _add_vendored_pynacl()
    try:
        from nacl.bindings import (
            crypto_box_SEALBYTES,
            crypto_box_keypair,
            crypto_box_seal,
            crypto_box_seal_open,
        )
    except ImportError as exc:
        raise RuntimeError(
            "PyNaCl is required for the memtest PoC. Install it with "
            "`python3 -m pip install --target .vendor/pynacl pynacl`."
        ) from exc
    return crypto_box_SEALBYTES, crypto_box_keypair, crypto_box_seal, crypto_box_seal_open


@dataclass
class CredentialContext:
    username: str
    password: str
    encoded_password: str


@dataclass
class MemTestFlowPlan:
    target_ip: str
    discovered: dict[str, object] | None
    credentials_required: bool
    credential_strings: list[str]
    password_codec_name: str
    send_stage_recovered: bool
    next_transport: str
    notes: list[str]


@dataclass
class MemTestPacketBuild:
    target_ip: str
    target_mac: str
    sender_key_id: int
    control_word_c2: int
    remote_key_hex: str
    clear_payload: bytes
    encrypted_blob: bytes
    udp_packet: bytes

    @property
    def packet_overhead(self) -> int:
        return len(self.udp_packet) - len(self.clear_payload)


@dataclass
class KeyExchangeResult:
    target_ip: str
    sender_key_id: int
    local_mac: str
    local_public_key_hex: str
    remote_key_hex: str
    remote_key_id: int | None
    control_word_c2: int | None
    target_mac: str | None
    decrypted_payload: bytes
    parsed: dict[str, object]


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _matrix_mul(left: tuple[tuple[float, ...], ...], right: tuple[tuple[float, ...], ...]) -> list[list[float]]:
    out_rows = len(left)
    inner = len(right)
    out_cols = len(right[0])
    out: list[list[float]] = []
    for row in range(out_rows):
        row_values: list[float] = []
        for col in range(out_cols):
            total = 0.0
            for idx in range(inner):
                total += left[row][idx] * right[idx][col]
            row_values.append(total)
        out.append(row_values)
    return out


def encode_memtest_password(password: str) -> str:
    raw = password.encode("utf-8")
    if not raw:
        return ""
    padded_len = (len(raw) + 7) & ~0x7
    padded = raw + (b"\x00" * (padded_len - len(raw)))
    blocks = [tuple(float(byte) for byte in padded[i : i + 8]) for i in range(0, padded_len, 8)]
    transformed = _matrix_mul(tuple(blocks), PASSWORD_FORWARD_MATRIX)
    out_chars: list[str] = []
    for block in transformed:
        for value in block:
            word = int(value) & 0xFFF
            out_chars.append(PASSWORD_ALPHABET[word & 0x3F])
            out_chars.append(PASSWORD_ALPHABET[(word >> 6) & 0x3F])
    return "".join(out_chars)


def decode_memtest_password(encoded: str) -> bytes:
    if not encoded:
        return b""
    if len(encoded) % 16 != 0:
        raise ValueError("encoded password length must be a multiple of 16")
    blocks: list[tuple[float, ...]] = []
    for offset in range(0, len(encoded), 16):
        row: list[float] = []
        for pair in range(0, 16, 2):
            lo = PASSWORD_REVERSE_TABLE[ord(encoded[offset + pair])]
            hi = PASSWORD_REVERSE_TABLE[ord(encoded[offset + pair + 1])]
            word = ((hi << 6) | lo) & 0xFFF
            if word & 0x800:
                word -= 0x1000
            row.append(float(word))
        blocks.append(tuple(row))
    decoded = _matrix_mul(tuple(blocks), PASSWORD_INVERSE_MATRIX)
    out = bytearray()
    for block in decoded:
        for value in block:
            out.append(int(math.trunc(value + PASSWORD_DECODE_EPSILON)) & 0xFF)
    return bytes(out)


def send_discovery_round(
    sock: socket.socket,
    packet_types: tuple[int, ...],
    target_ip: str,
    target_port: int,
    a4: int,
    a6: int,
    verbose: bool,
) -> None:
    for packet_type in packet_types:
        blob = build_probe_packet(packet_type=packet_type, a4=a4, a6=a6)
        sock.sendto(blob, (target_ip, target_port))
        if verbose:
            print(
                f"{now_text()} sent_probe "
                f"packet_type=0x{packet_type:02x} "
                f"target={target_ip}:{target_port} bytes={len(blob)}"
            )


def discover_target(
    target_ip: str,
    target_port: int,
    bind_send_port: int,
    listen_ports: tuple[int, ...],
    packet_types: tuple[int, ...],
    a4: int,
    a6: int,
    timeout: float,
    verbose: bool,
) -> DeviceState | None:
    listener, listen_port = bind_listener(listen_ports)
    sender = make_sender(bind_send_port)
    deadline = time.time() + timeout
    try:
        if verbose:
            print(
                f"{now_text()} discover_listening "
                f"local_port={listen_port} target={target_ip}:{target_port}"
            )
        while time.time() < deadline:
            send_discovery_round(
                sock=sender,
                packet_types=packet_types,
                target_ip=target_ip,
                target_port=target_port,
                a4=a4,
                a6=a6,
                verbose=verbose,
            )
            round_deadline = min(deadline, time.time() + 1.0)
            while time.time() < round_deadline:
                ready, _, _ = select.select([listener], [], [], 0.25)
                if not ready:
                    continue
                blob, addr = listener.recvfrom(65535)
                try:
                    parsed = parse_packet(blob)
                except Exception:
                    continue
                state = device_from_packet(parsed, src_ip=addr[0])
                if state is None:
                    continue
                if target_ip not in {"255.255.255.255", "0.0.0.0"} and addr[0] != target_ip:
                    continue
                return state
        return None
    finally:
        listener.close()
        sender.close()


def collect_credentials(username: str | None, password: str | None) -> CredentialContext:
    if not username:
        username = input("Administrator account: ").strip()
    if password is None:
        password = getpass.getpass("Enter the Admin's Password: ")
    return CredentialContext(
        username=username,
        password=password,
        encoded_password=encode_memtest_password(password),
    )


def normalize_remote_key_hex(text: str) -> str:
    value = "".join(text.strip().split()).lower()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) != 64:
        raise ValueError("remote key hex must be exactly 64 hex characters")
    int(value, 16)
    return value


def normalize_mac_text(text: str) -> str:
    return ":".join(f"{int(part, 16):02x}" for part in text.strip().split(":"))


def default_local_mac() -> str:
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in (40, 32, 24, 16, 8, 0))


def mac_text_to_bytes(text: str) -> bytes:
    parts = text.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {text}")
    return bytes(int(part, 16) for part in parts)


def build_u32_tlv(field_id: int, value: int) -> bytes:
    return bytes((field_id, 4)) + struct.pack("<I", value & 0xFFFFFFFF)


def build_u64_tlv(field_id: int, value: int) -> bytes:
    return bytes((field_id, 8)) + struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def build_string_tlv(field_id: int, value: str, *, encoding: str = "utf-8") -> bytes:
    payload = value.encode(encoding)
    if len(payload) > 0xFF:
        raise ValueError(f"field 0x{field_id:02x} payload too long: {len(payload)} bytes")
    return bytes((field_id, len(payload))) + payload


def field_map(parsed: dict[str, object]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for item in parsed.get("fields", []):
        if not isinstance(item, dict):
            continue
        field_id = item.get("field_id")
        if isinstance(field_id, str) and field_id not in result:
            result[field_id] = item
    return result


def field_int(parsed: dict[str, object], field_id: str) -> int | None:
    item = field_map(parsed).get(field_id)
    if not item:
        return None
    value = item.get("value")
    return value if isinstance(value, int) else None


def field_text(parsed: dict[str, object], field_id: str) -> str | None:
    item = field_map(parsed).get(field_id)
    if not item:
        return None
    value = item.get("value")
    if isinstance(value, str):
        return value
    raw = item.get("raw")
    if isinstance(raw, str):
        return raw
    return None


def build_key_exchange_clear_payload(
    local_mac: str,
    local_public_key_hex: str,
    sender_key_id: int,
    a4: int,
    a6: int,
    key_range: int = DEFAULT_KEY_EXCHANGE_RANGE,
) -> bytes:
    local_key = normalize_remote_key_hex(local_public_key_hex)
    fields = [
        build_u32_tlv(0xA4, a4),
        build_u32_tlv(0xA6, a6),
        build_u32_tlv(0x01, KEY_EXCHANGE_PACKET_TYPE),
        build_u64_tlv(0xB0, key_range),
        build_u64_tlv(0xB1, 0),
        build_u64_tlv(0xB8, key_range),
        build_u64_tlv(0xB9, 0),
        build_string_tlv(0x7C, normalize_mac_text(local_mac), encoding="ascii"),
        build_string_tlv(0xC4, local_key, encoding="ascii"),
        build_u32_tlv(0xC5, sender_key_id),
    ]
    return b"".join(fields)


def build_key_exchange_packet(
    local_mac: str,
    local_public_key_hex: str,
    sender_key_id: int,
    a4: int,
    a6: int,
) -> bytes:
    return CLEAR_HEADER + build_key_exchange_clear_payload(
        local_mac=local_mac,
        local_public_key_hex=local_public_key_hex,
        sender_key_id=sender_key_id,
        a4=a4,
        a6=a6,
    )


def build_memtest_clear_payload(
    target_mac: str,
    username: str,
    encoded_password: str,
    control_word_c2: int,
    sender_key_id: int,
    a4: int,
    a6: int,
) -> bytes:
    mac_value = target_mac.lower()
    fields = [
        build_u32_tlv(0xA4, a4),
        build_u32_tlv(0xA6, a6),
        build_u32_tlv(0x01, MEMTEST_PACKET_TYPE),
        build_string_tlv(0x19, mac_value, encoding="ascii"),
        build_string_tlv(0x2A, encoded_password, encoding="ascii"),
        build_string_tlv(0x4A, username),
        build_u32_tlv(0xC2, control_word_c2),
        build_u32_tlv(0xC5, sender_key_id),
    ]
    return b"".join(fields)


def seal_memtest_payload(clear_payload: bytes, remote_key_hex: str) -> bytes:
    seal_bytes, _, crypto_box_seal, _ = require_nacl_bindings()
    remote_public_key = bytes.fromhex(normalize_remote_key_hex(remote_key_hex))
    encrypted = crypto_box_seal(clear_payload, remote_public_key)
    if len(encrypted) != len(clear_payload) + seal_bytes:
        raise RuntimeError(
            f"unexpected sealed-box length: got {len(encrypted)}, expected {len(clear_payload) + seal_bytes}"
        )
    return encrypted


def build_memtest_packet(
    *,
    target_ip: str,
    target_mac: str,
    username: str,
    encoded_password: str,
    remote_key_hex: str,
    control_word_c2: int,
    sender_key_id: int,
    a4: int,
    a6: int,
) -> MemTestPacketBuild:
    clear_payload = build_memtest_clear_payload(
        target_mac=target_mac,
        username=username,
        encoded_password=encoded_password,
        control_word_c2=control_word_c2,
        sender_key_id=sender_key_id,
        a4=a4,
        a6=a6,
    )
    encrypted_blob = seal_memtest_payload(clear_payload, remote_key_hex)
    udp_packet = ALT_HEADER + encrypted_blob
    return MemTestPacketBuild(
        target_ip=target_ip,
        target_mac=target_mac.lower(),
        sender_key_id=sender_key_id & 0xFFFFFFFF,
        control_word_c2=control_word_c2 & 0xFFFFFFFF,
        remote_key_hex=normalize_remote_key_hex(remote_key_hex),
        clear_payload=clear_payload,
        encrypted_blob=encrypted_blob,
        udp_packet=udp_packet,
    )


def send_memtest_packet(packet: MemTestPacketBuild, target_port: int, bind_send_port: int, verbose: bool) -> None:
    sender = make_sender(bind_send_port)
    try:
        sender.sendto(packet.udp_packet, (packet.target_ip, target_port))
        if verbose:
            print(
                f"{now_text()} memtest_packet_sent "
                f"target={packet.target_ip}:{target_port} "
                f"bytes={len(packet.udp_packet)} "
                f"clear_bytes={len(packet.clear_payload)} "
                f"sealed_bytes={len(packet.encrypted_blob)}"
            )
    finally:
        sender.close()


def fetch_remote_key(
    *,
    target_ip: str,
    target_port: int,
    bind_send_port: int,
    listen_ports: tuple[int, ...],
    local_mac: str,
    a4: int,
    a6: int,
    timeout: float,
    verbose: bool,
    dump_packet_hex: bool = False,
    dump_response_hex: bool = False,
) -> KeyExchangeResult:
    _, crypto_box_keypair, _, crypto_box_seal_open = require_nacl_bindings()
    local_public_key, local_secret_key = crypto_box_keypair()
    sender_key_id = secrets.randbits(32)
    packet = build_key_exchange_packet(
        local_mac=local_mac,
        local_public_key_hex=local_public_key.hex(),
        sender_key_id=sender_key_id,
        a4=a4,
        a6=a6,
    )
    listener, listen_port = bind_listener(listen_ports)
    sender = make_sender(bind_send_port)
    send_targets = [target_ip]
    if target_ip not in {"255.255.255.255", "0.0.0.0"}:
        send_targets.append("255.255.255.255")
    deadline = time.time() + timeout
    seen_packets = 0
    seen_from_target = 0
    seen_alt_from_target = 0
    decrypt_failures = 0
    decrypted_without_key = 0
    try:
        if verbose:
            print(
                f"{now_text()} key_exchange_listening "
                f"local_port={listen_port} local_mac={normalize_mac_text(local_mac)} "
                f"sender_key_id=0x{sender_key_id:08x}"
            )
        if dump_packet_hex:
            print(f"{now_text()} key_exchange_packet_hex={packet.hex()}")
        for dst in send_targets:
            sender.sendto(packet, (dst, target_port))
            if verbose:
                print(
                    f"{now_text()} key_exchange_sent "
                    f"target={dst}:{target_port} bytes={len(packet)} "
                    f"fields={[f'0x{field_id:02x}' for field_id in KEY_EXCHANGE_FIELD_ORDER]}"
                )
        while time.time() < deadline:
            ready, _, _ = select.select([listener], [], [], 0.25)
            if not ready:
                continue
            blob, addr = listener.recvfrom(65535)
            seen_packets += 1
            if addr[0] != target_ip:
                continue
            seen_from_target += 1
            if not blob.startswith(ALT_HEADER):
                if verbose:
                    header_hex = blob[:8].hex() if len(blob) >= 8 else blob.hex()
                    packet_summary = ""
                    if blob.startswith(CLEAR_HEADER):
                        try:
                            parsed_clear = parse_packet(blob)
                            packet_summary = (
                                f" packet={parsed_clear.get('packet_type_name') or parsed_clear.get('packet_type_value')} "
                                f"fields={[item.get('field_id') for item in parsed_clear.get('fields', []) if isinstance(item, dict)]}"
                            )
                        except Exception:
                            packet_summary = ""
                    print(
                        f"{now_text()} key_exchange_ignore "
                        f"src={addr[0]} bytes={len(blob)} header={header_hex}{packet_summary}"
                    )
                if dump_response_hex:
                    print(f"{now_text()} key_exchange_clear_response_hex={blob.hex()}")
                continue
            seen_alt_from_target += 1
            if dump_response_hex:
                print(f"{now_text()} key_exchange_alt_response_hex={blob.hex()}")
            try:
                decrypted = crypto_box_seal_open(blob[8:], local_public_key, local_secret_key)
            except Exception as exc:
                decrypt_failures += 1
                if verbose:
                    print(
                        f"{now_text()} key_exchange_decrypt_skip "
                        f"src={addr[0]} bytes={len(blob)} sealed_bytes={len(blob) - 8} reason={exc}"
                    )
                continue
            if decrypted.startswith(CLEAR_HEADER) or decrypted.startswith(ALT_HEADER):
                parsed = parse_packet(decrypted)
            else:
                parsed = parse_packet(CLEAR_HEADER + decrypted)
            remote_key = field_text(parsed, "0xc4")
            if not remote_key:
                decrypted_without_key += 1
                if verbose:
                    packet_type = parsed.get("packet_type_name") or parsed.get("packet_type_value")
                    print(
                        f"{now_text()} key_exchange_decrypt_skip "
                        f"src={addr[0]} reason=no_0xc4 packet={packet_type}"
                    )
                continue
            remote_key = normalize_remote_key_hex(remote_key)
            return KeyExchangeResult(
                target_ip=target_ip,
                sender_key_id=sender_key_id,
                local_mac=normalize_mac_text(local_mac),
                local_public_key_hex=local_public_key.hex(),
                remote_key_hex=remote_key,
                remote_key_id=field_int(parsed, "0xc6") if field_int(parsed, "0xc6") is not None else field_int(parsed, "0xc5"),
                control_word_c2=field_int(parsed, "0xc2"),
                target_mac=field_text(parsed, "0x19"),
                decrypted_payload=decrypted,
                parsed=parsed,
            )
    finally:
        listener.close()
        sender.close()
    raise TimeoutError(
        f"no decryptable key-exchange response from {target_ip} within {timeout:.1f}s "
        f"(seen={seen_packets}, from_target={seen_from_target}, "
        f"alt_from_target={seen_alt_from_target}, decrypt_failures={decrypt_failures}, "
        f"decrypted_without_key={decrypted_without_key})"
    )


def build_flow_plan(target_ip: str, state: DeviceState | None, creds: CredentialContext | None) -> MemTestFlowPlan:
    discovered = None
    if state is not None:
        discovered = {
            "ip": state.display_ip,
            "mac": state.mac,
            "name": state.name,
            "model": state.model,
            "platform": state.platform,
            "serial": state.serial,
            "status_value": state.status_value,
            "status_name": state.status_name,
        }
    notes = [
        "UI side is confirmed: slotMemTestTrigged() exists and opens a dedicated memory-test wizard.",
        "The memory-test wizard contains an explicit admin credential page.",
        "Recovered strings: Enter the Admin's Password / Administrator account: / Hint:.",
        "slotMaintainCommitPage(int) fetches ConfirmPasswd and ConfirmAccount, then calls 0x45b0c0(account, password, nas, 1).",
        "Inside 0x45b0c0 the password goes through QString::toUtf8_helper -> snprintf -> 0x47d010.",
        "0x47d010 is a custom 8-byte block codec: matrix multiply plus 64-character alphabet encoding, not QCryptographicHash.",
        "0x47d1c0 is the matching decode helper; the pair is also wrapped by generic QString encode/decode helpers at 0x44bc17 and 0x44bd2e.",
        "The account is copied with QString::toLocal8Bit_helper into the request structure at NASINFO-like offset +0xc24.",
        "The clear memtest payload sets packet_type at +0xed0 to 0x0c, then 0x4abe80 builds the field list.",
        "0x2a maps to the encoded password string at +0x74, and 0x4a maps to the admin account string at +0xc24.",
        "0xc5 is the local key ID from 0x4affb0; 0xc6 is a per-device remote key ID used with MAC for key lookup; 0xc4 is the 0x40-byte key string.",
        "0xc2 is a u32 control word at +0x2f40 cloned from NASINFO and echoed into encrypted control requests; no fresh computation site is used in the memtest path.",
        "Because 0x4ab220 only treats 0x01 and 0x13 as request-class, packet_type 0x0c takes the encrypted alt-header path via 0x4abb00 before 0x4ac900 sends it.",
        "The encrypted wrapper matches libsodium crypto_box_seal: 32-byte ephemeral public key + 16-byte MAC+ciphertext, prefixed by alt header 1234556653594e4f.",
        "The 24-byte nonce is produced with blake2b(ephemeral_public_key || remote_public_key, digest_size=24).",
        "The binary does contain http://sy.to/encryptpassword, but that URL is not on the confirmed memtest auth/send chain above.",
    ]
    if creds is not None:
        notes.append(f"Current run collected administrator account: {creds.username}")
        notes.append(f"Recovered password codec output length for this run: {len(creds.encoded_password)}")
    return MemTestFlowPlan(
        target_ip=target_ip,
        discovered=discovered,
        credentials_required=True,
        credential_strings=[
            "Enter the Admin's Password",
            "Administrator account:",
            "Hint:",
        ],
        password_codec_name="custom_8byte_matrix_codec_from_0x47d010",
        send_stage_recovered=True,
        next_transport="confirmed UDP control send via 0x4ac900 after 0x4abe80 request build",
        notes=notes,
    )


def wait_for_memory_test(
    target_ip: str,
    target_port: int,
    bind_send_port: int,
    listen_ports: tuple[int, ...],
    packet_types: tuple[int, ...],
    a4: int,
    a6: int,
    timeout: float,
    verbose: bool,
) -> DeviceState | None:
    listener, listen_port = bind_listener(listen_ports)
    sender = make_sender(bind_send_port)
    deadline = time.time() + timeout
    try:
        if verbose:
            print(
                f"{now_text()} waiting_memtest "
                f"local_port={listen_port} target={target_ip}:{target_port}"
            )
        while time.time() < deadline:
            send_discovery_round(
                sock=sender,
                packet_types=packet_types,
                target_ip=target_ip,
                target_port=target_port,
                a4=a4,
                a6=a6,
                verbose=verbose,
            )
            ready, _, _ = select.select([listener], [], [], 1.0)
            if not ready:
                continue
            blob, addr = listener.recvfrom(65535)
            try:
                parsed = parse_packet(blob)
            except Exception:
                continue
            state = device_from_packet(parsed, src_ip=addr[0])
            if state is None:
                continue
            if target_ip not in {"255.255.255.255", "0.0.0.0"} and addr[0] != target_ip:
                continue
            if state.status_value == 9:
                return state
        return None
    finally:
        listener.close()
        sender.close()


def monitor_memory_test_progress(
    target_ip: str,
    target_port: int,
    bind_send_port: int,
    listen_ports: tuple[int, ...],
    packet_types: tuple[int, ...],
    a4: int,
    a6: int,
    timeout: float,
    verbose: bool,
) -> DeviceState | None:
    listener, listen_port = bind_listener(listen_ports)
    sender = make_sender(bind_send_port)
    deadline = time.time() + timeout
    last_signature: tuple[int | None, int | None, str | None] | None = None
    last_state: DeviceState | None = None
    seen_memtest = False
    try:
        if verbose:
            print(
                f"{now_text()} monitoring_memtest "
                f"local_port={listen_port} target={target_ip}:{target_port} timeout={timeout:.1f}"
            )
        while time.time() < deadline:
            send_discovery_round(
                sock=sender,
                packet_types=packet_types,
                target_ip=target_ip,
                target_port=target_port,
                a4=a4,
                a6=a6,
                verbose=verbose,
            )
            round_deadline = min(deadline, time.time() + 1.0)
            while time.time() < round_deadline:
                ready, _, _ = select.select([listener], [], [], 0.25)
                if not ready:
                    continue
                blob, addr = listener.recvfrom(65535)
                try:
                    parsed = parse_packet(blob)
                except Exception:
                    continue
                state = device_from_packet(parsed, src_ip=addr[0])
                if state is None:
                    continue
                if target_ip not in {"255.255.255.255", "0.0.0.0"} and addr[0] != target_ip:
                    continue
                signature = (state.status_value, state.progress_raw_x100, state.status_name)
                if signature != last_signature:
                    print(format_state(state))
                    last_signature = signature
                last_state = state
                if state.status_value == 9:
                    seen_memtest = True
                elif seen_memtest:
                    print(f"{now_text()} memory_test_monitor completed_or_left_memtest_state")
                    return state
        if last_state is None:
            print(f"{now_text()} memory_test_monitor timeout={timeout:.1f} status=no_status_packet")
        else:
            print(f"{now_text()} memory_test_monitor timeout={timeout:.1f} status=last_state_reported")
        return last_state
    finally:
        listener.close()
        sender.close()


def parse_port_list(text: str) -> tuple[int, ...]:
    values: list[int] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if chunk:
            values.append(int(chunk, 0))
    if not values:
        raise ValueError("no listen ports configured")
    return tuple(values)


def parse_packet_types(text: str) -> tuple[int, ...]:
    values: list[int] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if chunk:
            values.append(int(chunk, 0))
    if not values:
        raise ValueError("no packet types configured")
    return tuple(values)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reverse-engineered Synology Assistant memory-test flow helper.")
    parser.add_argument("--target-ip", help="target NAS IPv4 address")
    parser.add_argument("--target-port", type=int, default=DEFAULT_SEND_PORT, help="Assistant UDP discovery port")
    parser.add_argument("--listen-ports", default="9999,9998,9997", help="comma-separated local listen ports")
    parser.add_argument("--bind-send-port", type=int, default=DEFAULT_SEND_BIND_PORT, help="preferred local send port")
    parser.add_argument("--packet-types", default="0x0f,0x01", help="comma-separated discovery packet types")
    parser.add_argument("--a4", type=lambda s: int(s, 0), default=DEFAULT_A4, help="field 0xA4 u32")
    parser.add_argument("--a6", type=lambda s: int(s, 0), default=DEFAULT_A6, help="field 0xA6 u32")
    parser.add_argument("--discover-timeout", type=float, default=DEFAULT_DISCOVERY_TIMEOUT, help="discovery timeout seconds")
    parser.add_argument("--skip-discovery", action="store_true", help="skip initial status discovery and go directly to the requested action")
    parser.add_argument(
        "--wait-memory-test",
        type=float,
        default=0.0,
        help="wait up to N seconds for status=9; when combined with --send-memtest this runs after sending",
    )
    parser.add_argument(
        "--monitor-progress",
        type=float,
        default=0.0,
        help="poll and print memory-test status/progress changes for N seconds; runs after --send-memtest when used together",
    )
    parser.add_argument("--username", help="administrator account")
    parser.add_argument("--password", help="administrator password")
    parser.add_argument("--no-credentials", action="store_true", help="skip prompting for credentials")
    parser.add_argument("--json", action="store_true", help="print plan as JSON")
    parser.add_argument("--show-encoded-password", action="store_true", help="print 0x47d010-style encoded password")
    parser.add_argument("--self-test-codec", action="store_true", help="run local encode/decode codec checks and exit")
    parser.add_argument("--self-test-seal", action="store_true", help="run local sealed-box checks and exit")
    parser.add_argument("--fetch-remote-key", action="store_true", help="actively fetch and decrypt the target NAS public key")
    parser.add_argument("--local-mac", help="local adapter MAC for field 0x7C in key exchange; defaults to uuid.getnode()")
    parser.add_argument("--key-timeout", type=float, default=5.0, help="key exchange timeout seconds")
    parser.add_argument("--dump-key-exchange-json", action="store_true", help="print decrypted key-exchange response JSON")
    parser.add_argument("--dump-key-exchange-packet-hex", action="store_true", help="print key-exchange request packet hex")
    parser.add_argument("--dump-key-exchange-response-hex", action="store_true", help="print key-exchange candidate response packets as hex")
    parser.add_argument("--remote-key-hex", help="64-hex-character remote public key used by the memtest sealed box")
    parser.add_argument("--sender-key-id", type=lambda s: int(s, 0), help="override field 0xC5 sender key id")
    parser.add_argument(
        "--control-word-c2",
        type=lambda s: int(s, 0),
        help="override field 0xC2 control word; defaults to fetched 0xC2 or 0",
    )
    parser.add_argument("--target-mac", help="override target MAC if discovery is skipped or incomplete")
    parser.add_argument("--dump-packet-hex", action="store_true", help="print the final UDP packet as hex")
    parser.add_argument("--dry-run-packet", action="store_true", help="build the memtest packet without sending it")
    parser.add_argument("--send-memtest", action="store_true", help="build and send the memtest UDP control packet")
    parser.add_argument("--verbose", action="store_true", help="print probe activity")
    args = parser.parse_args()

    if args.self_test_codec:
        cases = ["", "admin", "123456", "P@ssw0rd!", "中文Pass123"]
        for case in cases:
            encoded = encode_memtest_password(case)
            decoded = decode_memtest_password(encoded)
            raw = case.encode("utf-8")
            padded_len = (len(raw) + 7) & ~0x7 if case else 0
            expected_len = padded_len * 2
            if len(encoded) != expected_len or decoded[: len(raw)] != raw:
                print(f"{now_text()} codec_self_test case={case!r} result=failed")
                return 1
            print(
                f"{now_text()} codec_self_test "
                f"case={case!r} encoded_len={len(encoded)} expected_len={expected_len} roundtrip=yes"
            )
        return 0

    if args.self_test_seal:
        seal_bytes, crypto_box_keypair, crypto_box_seal, crypto_box_seal_open = require_nacl_bindings()
        public_key, secret_key = crypto_box_keypair()
        message = b"synology-memtest-poc"
        sealed = crypto_box_seal(message, public_key)
        if len(sealed) != len(message) + seal_bytes:
            print(f"{now_text()} seal_self_test result=failed reason=wrong_overhead")
            return 1
        opened = crypto_box_seal_open(sealed, public_key, secret_key)
        if opened != message:
            print(f"{now_text()} seal_self_test result=failed reason=decrypt_mismatch")
            return 1
        print(
            f"{now_text()} seal_self_test "
            f"result=ok message_len={len(message)} sealed_len={len(sealed)} overhead={seal_bytes}"
        )
        return 0

    if not args.target_ip:
        parser.error("the following arguments are required: --target-ip")

    listen_ports = parse_port_list(args.listen_ports)
    packet_types = parse_packet_types(args.packet_types)

    state = None
    if not args.skip_discovery:
        state = discover_target(
            target_ip=args.target_ip,
            target_port=args.target_port,
            bind_send_port=args.bind_send_port,
            listen_ports=listen_ports,
            packet_types=packet_types,
            a4=args.a4,
            a6=args.a6,
            timeout=args.discover_timeout,
            verbose=args.verbose,
        )

    creds = None
    if not args.no_credentials:
        creds = collect_credentials(username=args.username, password=args.password)

    plan = build_flow_plan(target_ip=args.target_ip, state=state, creds=creds)

    if args.json:
        print(json.dumps(asdict(plan), ensure_ascii=False, indent=2))
    else:
        print(f"{now_text()} memtest_flow target={plan.target_ip}")
        if state is not None:
            print(format_state(state))
        else:
            print(f"{now_text()} discover_result target={args.target_ip} status=not_found")
        print(f"{now_text()} credentials_required={plan.credentials_required} send_stage_recovered={plan.send_stage_recovered}")
        print(f"{now_text()} password_codec={plan.password_codec_name}")
        print(f"{now_text()} next_transport={plan.next_transport}")
        for note in plan.notes:
            print(f"{now_text()} note={note}")

    key_result = None
    remote_key_hex = args.remote_key_hex
    need_packet_key = args.send_memtest or args.dry_run_packet
    if args.fetch_remote_key or (need_packet_key and not remote_key_hex):
        key_result = fetch_remote_key(
            target_ip=args.target_ip,
            target_port=args.target_port,
            bind_send_port=args.bind_send_port,
            listen_ports=listen_ports,
            local_mac=args.local_mac or default_local_mac(),
            a4=args.a4,
            a6=args.a6,
            timeout=args.key_timeout,
            verbose=args.verbose,
            dump_packet_hex=args.dump_key_exchange_packet_hex,
            dump_response_hex=args.dump_key_exchange_response_hex,
        )
        remote_key_hex = key_result.remote_key_hex
        print(
            f"{now_text()} key_exchange_result "
            f"target={key_result.target_ip} "
            f"target_mac={key_result.target_mac or 'unknown'} "
            f"sender_key_id=0x{key_result.sender_key_id:08x} "
            f"remote_key_id={f'0x{key_result.remote_key_id:08x}' if key_result.remote_key_id is not None else 'unknown'} "
            f"control_word_c2={f'0x{key_result.control_word_c2:08x}' if key_result.control_word_c2 is not None else 'unknown'} "
            f"remote_key_hex={key_result.remote_key_hex}"
        )
        if args.dump_key_exchange_json:
            print(json.dumps(key_result.parsed, ensure_ascii=False, indent=2))

    if args.send_memtest or args.dry_run_packet:
        if creds is None:
            raise RuntimeError("credentials are required to build a memtest packet")
        target_mac = args.target_mac or (key_result.target_mac if key_result else None) or (state.mac if state else None)
        if not target_mac:
            raise RuntimeError("target MAC is required; provide --target-mac or allow discovery to find it")
        if not remote_key_hex:
            raise RuntimeError("remote public key is required; provide --remote-key-hex or --fetch-remote-key")
        sender_key_id = args.sender_key_id
        if sender_key_id is None:
            sender_key_id = key_result.sender_key_id if key_result else secrets.randbits(32)
        control_word_c2 = args.control_word_c2
        if control_word_c2 is None:
            control_word_c2 = key_result.control_word_c2 if key_result and key_result.control_word_c2 is not None else DEFAULT_MEMTEST_CONTROL_WORD
        packet = build_memtest_packet(
            target_ip=args.target_ip,
            target_mac=target_mac,
            username=creds.username,
            encoded_password=creds.encoded_password,
            remote_key_hex=remote_key_hex,
            control_word_c2=control_word_c2,
            sender_key_id=sender_key_id,
            a4=args.a4,
            a6=args.a6,
        )
        print(
            f"{now_text()} memtest_packet "
            f"target={packet.target_ip}:{args.target_port} "
            f"target_mac={packet.target_mac} "
            f"sender_key_id=0x{packet.sender_key_id:08x} "
            f"control_word_c2=0x{packet.control_word_c2:08x} "
            f"clear_bytes={len(packet.clear_payload)} "
            f"sealed_bytes={len(packet.encrypted_blob)} "
            f"udp_bytes={len(packet.udp_packet)} "
            f"overhead={packet.packet_overhead}"
        )
        print(
            f"{now_text()} memtest_fields "
            f"order={[f'0x{field_id:02x}' for field_id in MEMTEST_FIELD_ORDER]}"
        )
        if args.dump_packet_hex:
            print(f"{now_text()} memtest_packet_hex={packet.udp_packet.hex()}")
        if args.send_memtest:
            send_memtest_packet(
                packet=packet,
                target_port=args.target_port,
                bind_send_port=args.bind_send_port,
                verbose=args.verbose,
            )

    if args.wait_memory_test > 0:
        result = wait_for_memory_test(
            target_ip=args.target_ip,
            target_port=args.target_port,
            bind_send_port=args.bind_send_port,
            listen_ports=listen_ports,
            packet_types=packet_types,
            a4=args.a4,
            a6=args.a6,
            timeout=args.wait_memory_test,
            verbose=args.verbose,
        )
        if result is None:
            print(f"{now_text()} memory_test_wait timeout={args.wait_memory_test}")
            return 1
        print(format_state(result))

    if args.monitor_progress > 0:
        monitor_memory_test_progress(
            target_ip=args.target_ip,
            target_port=args.target_port,
            bind_send_port=args.bind_send_port,
            listen_ports=listen_ports,
            packet_types=packet_types,
            a4=args.a4,
            a6=args.a6,
            timeout=args.monitor_progress,
            verbose=args.verbose,
        )

    if creds is not None:
        print(
            f"{now_text()} auth_summary "
            f"username={creds.username} "
            f"password_collected=yes "
            f"encoded_password_len={len(creds.encoded_password)}"
        )
        if args.show_encoded_password:
            print(f"{now_text()} encoded_password={creds.encoded_password}")

    if args.wait_memory_test <= 0 and args.monitor_progress <= 0 and not args.send_memtest and not args.dry_run_packet:
        if key_result is not None:
            print(
                f"{now_text()} next_step "
                "remote key was fetched; add --username/--password with --dry-run-packet or --send-memtest to build/send the memtest packet"
            )
        else:
            print(
                f"{now_text()} next_step "
                "password codec, sealed-box wrapper, and memtest packet builder are confirmed; use --fetch-remote-key or provide --remote-key-hex to build/send a real memtest packet"
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, TimeoutError, ValueError) as exc:
        print(f"{now_text()} error={exc}", file=sys.stderr)
        raise SystemExit(2)
