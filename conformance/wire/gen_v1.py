import struct

MAGIC = b"KWP1"
REQ, RSP = 1, 2
HELLO, PING, KEYGEN, AEADENC, AEADDEC, SIGN, VERIFY, RANDOM = 0x1, 0x2, 0x10, 0x20, 0x21, 0x22, 0x23, 0x40
KEYINSPECT, KEYEXPORT, KEYIMPORT = 0x11, 0x30, 0x31
OK, PROTOCOL, CRYPTO = 0, 1, 6


def hdr(kind, status, op, id_, ln):
    return MAGIC + bytes([kind, status]) + struct.pack(">HII", op, id_, ln)


def u8(v): return bytes([v])
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)
def b(x): return u32(len(x)) + x
def s(x): return b(x.encode())


def frame(kind, op, id_, body, status=0):
    return hdr(kind, status, op, id_, len(body)) + body


blob = bytes((0xA0 + i) & 0xFF for i in range(40))
pk = b"\x04" + bytes(range(64))
sig = bytes(range(0x40, 0x40 + 64))
ct = bytes((0xC0 + i) & 0xFF for i in range(65))
kid = bytes(range(16))
kid2 = bytes(range(16, 32))
pkg = bytes((0xD0 + i) & 0xFF for i in range(120))
kempk = b"\x04" + bytes(range(0x80, 0x80 + 64))

frames = [
    ("hello_request", frame(REQ, HELLO, 1, u32(1))),
    ("hello_response", frame(RSP, HELLO, 1, u32(1) + u64(3) + s("aws-lc-rs") + s("1.18.2"))),
    ("ping_request", frame(REQ, PING, 2, b"")),
    ("ping_response", frame(RSP, PING, 2, b"")),
    ("key_generate_request", frame(REQ, KEYGEN, 3, u16(1) + u32(3) + s("tenant-a/db"))),
    ("key_generate_response_sym", frame(RSP, KEYGEN, 3, b(kid) + b(blob) + b(b""))),
    ("key_generate_request_pqc", frame(REQ, KEYGEN, 5, u16(0x100) + u32(4) + s(""))),
    ("key_generate_response_asym", frame(RSP, KEYGEN, 5, b(kid2) + b(blob) + b(pk))),
    ("aead_encrypt_request", frame(REQ, AEADENC, 4, b(blob) + b(b"hello") + b(b"ctx"))),
    ("aead_encrypt_response", frame(RSP, AEADENC, 4, b(ct))),
    ("aead_decrypt_request", frame(REQ, AEADDEC, 6, b(blob) + b(ct) + b(b"ctx"))),
    ("aead_decrypt_response", frame(RSP, AEADDEC, 6, b(b"hello"))),
    ("aead_encrypt_request_empty", frame(REQ, AEADENC, 12, b(blob) + b(b"") + b(b""))),
    ("sign_request", frame(REQ, SIGN, 7, b(blob) + b(b"message"))),
    ("sign_response", frame(RSP, SIGN, 7, b(sig))),
    ("verify_request", frame(REQ, VERIFY, 8, u16(0x10) + b(pk) + b(b"message") + b(sig))),
    ("verify_response_true", frame(RSP, VERIFY, 8, u8(1))),
    ("verify_response_false", frame(RSP, VERIFY, 9, u8(0))),
    ("random_request", frame(REQ, RANDOM, 10, u32(32))),
    ("random_response", frame(RSP, RANDOM, 10, b(bytes(range(32))))),
    ("random_request_max", frame(REQ, RANDOM, 13, u32(1024))),
    ("error_response_crypto", hdr(RSP, CRYPTO, AEADENC, 4, 0)),
    ("error_response_protocol", hdr(RSP, PROTOCOL, 0xFFFF, 0, 0)),
    ("ping_request_max_id", frame(REQ, PING, 0xFFFFFFFF, b"")),
    ("key_inspect_request", frame(REQ, KEYINSPECT, 14, b(blob))),
    ("key_inspect_response", frame(RSP, KEYINSPECT, 14, u16(1) + u32(0x103) + b(kid) + s("tenant-a/db"))),
    ("key_export_request", frame(REQ, KEYEXPORT, 15, b(blob) + u16(0x30) + b(kempk) + u32(2) + b(b"from=a;to=b"))),
    ("key_export_response", frame(RSP, KEYEXPORT, 15, b(pkg))),
    ("key_import_request", frame(REQ, KEYIMPORT, 16, b(blob) + b(pkg) + b(b"from=a;to=b"))),
    ("key_import_response", frame(RSP, KEYIMPORT, 16, b(kid) + b(blob) + u16(1) + u32(2) + s("tenant-a/db"))),
    ("key_export_request_hybrid_empty_context", frame(REQ, KEYEXPORT, 17, b(blob) + u16(0x210) + b(bytes(1249)) + u32(0x102) + b(b""))),
]

reject_headers = [
    ("bad_magic", b"KWP0" + bytes([REQ, 0]) + struct.pack(">HII", PING, 1, 0)),
    ("bad_magic_lower", b"kwp1" + bytes([REQ, 0]) + struct.pack(">HII", PING, 1, 0)),
    ("bad_kind_zero", hdr(0, 0, PING, 1, 0)),
    ("bad_kind_three", hdr(3, 0, PING, 1, 0)),
    ("request_with_status", hdr(REQ, 1, PING, 1, 0)),
    ("error_with_body", hdr(RSP, 1, PING, 1, 4)),
    ("unknown_status", hdr(RSP, 200, PING, 1, 0)),
    ("unknown_status_ten", hdr(RSP, 10, PING, 1, 0)),
    ("body_too_large", hdr(REQ, 0, PING, 1, (1 << 20) + 1)),
    ("body_too_large_max", hdr(REQ, 0, PING, 1, 0xFFFFFFFF)),
]

reject_bodies = [
    ("hello_request_trailing", HELLO, REQ, u32(1) + b"\x00"),
    ("hello_request_truncated", HELLO, REQ, b"\x00\x00\x00"),
    ("hello_request_empty", HELLO, REQ, b""),
    ("ping_request_nonempty", PING, REQ, b"\x00"),
    ("ping_response_nonempty", PING, RSP, b"\x00"),
    ("key_generate_response_short_id", KEYGEN, RSP, b(bytes(15)) + b(blob) + b(b"")),
    ("key_generate_response_long_id", KEYGEN, RSP, b(bytes(17)) + b(blob) + b(b"")),
    ("key_generate_request_label_too_long", KEYGEN, REQ, u16(1) + u32(1) + b(b"a" * 257)),
    ("key_generate_request_label_bad_utf8", KEYGEN, REQ, u16(1) + u32(1) + b(b"\xff\xfe")),
    ("random_request_too_large", RANDOM, REQ, u32(1025)),
    ("random_response_too_large", RANDOM, RSP, b(bytes(1025))),
    ("verify_response_bad_bool", VERIFY, RSP, u8(2)),
    ("verify_response_bad_bool_ff", VERIFY, RSP, u8(0xFF)),
    ("hello_response_bad_utf8", HELLO, RSP, u32(1) + u64(0) + b(b"\xff\xfe") + s("x")),
    ("hello_response_name_too_long", HELLO, RSP, u32(1) + u64(0) + b(b"a" * 65) + s("x")),
    ("aead_encrypt_request_length_overrun", AEADENC, REQ, b(blob) + u32(10) + b"abc"),
    ("aead_encrypt_request_length_too_large", AEADENC, REQ, b(blob) + u32(65537)),
    ("aead_encrypt_response_too_large", AEADENC, RSP, u32(65601) + b"\x00" * 65601),
    ("sign_request_blob_too_large", SIGN, REQ, u32(16385) + b"\x00" * 16385 + b(b"m")),
    ("unknown_op_body", 0x7777, REQ, b""),
    ("key_inspect_request_trailing", KEYINSPECT, REQ, b(blob) + b"\x00"),
    ("key_inspect_response_label_too_long", KEYINSPECT, RSP, u16(1) + u32(1) + b(kid) + b(b"a" * 257)),
    ("key_export_request_context_too_long", KEYEXPORT, REQ, b(blob) + u16(0x30) + b(kempk) + u32(2) + b(b"\x00" * 1025)),
    ("key_export_response_package_too_large", KEYEXPORT, RSP, u32(8193) + b"\x00" * 8193),
    ("key_import_request_truncated", KEYIMPORT, REQ, b(blob) + u32(5) + b"ab"),
    ("key_import_response_short_id", KEYIMPORT, RSP, b(bytes(15)) + b(blob) + u16(1) + u32(2) + s("")),
]

out = ["# kms wire protocol v1 conformance vectors", "# frame <name> <hex>", "# reject_header <name> <hex>", "# reject_body <name> <op> <req|rsp> <hex>", ""]
for n, f in frames:
    out.append(f"frame {n} {f.hex()}")
out.append("")
for n, h in reject_headers:
    assert len(h) == 16
    out.append(f"reject_header {n} {h.hex()}")
out.append("")
for n, op, kind, body in reject_bodies:
    out.append(f"reject_body {n} 0x{op:04x} {'req' if kind == REQ else 'rsp'} {body.hex()}")
import pathlib
pathlib.Path(__file__).resolve().with_name("v1.txt").write_text("\n".join(out) + "\n")
print(len(frames), len(reject_headers), len(reject_bodies))
