#!/usr/bin/env python3
"""
Convert the official Ascon-AEAD128 KAT file (ascon-c, LWC_AEAD_KAT_128_128.txt)
into a word stream for the Verilog testbench, and cross-check every vector
against pyascon.

Usage: python3 gen_vectors.py <LWC_AEAD_KAT_128_128.txt> <pyascon_dir> <out.hex>

Stream per vector (32-bit words, little-endian bytes inside each word):
  header = (adlen << 16) | ptlen
  key[4], nonce[4]
  AD   : (adlen//16 + 1) blocks x 4 words   (only if adlen > 0)
  PT   : (ptlen//16 + 1) blocks x 4 words
  CT   : (ptlen//16 + 1) blocks x 4 words   (ciphertext without tag)
  TAG  : 4 words
Terminator: FFFFFFFF
"""
import sys

kat_path, pyascon_dir, out_path = sys.argv[1:4]
sys.path.insert(0, pyascon_dir)
import ascon  # noqa: E402


def words(b):
    assert len(b) % 4 == 0
    return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]


def blocks(b):
    n = len(b) // 16 + 1          # full blocks + one final block (0..15 bytes)
    return b + bytes(n * 16 - len(b))


out = []
count = 0
for rec in open(kat_path).read().strip().split("\n\n"):
    d = {}
    for line in rec.splitlines():
        k, _, v = line.partition(" =")
        d[k.strip()] = v.strip()
    key, nonce = bytes.fromhex(d["Key"]), bytes.fromhex(d["Nonce"])
    pt, ad, ctt = (bytes.fromhex(d[x]) for x in ("PT", "AD", "CT"))
    assert ascon.ascon_encrypt(key, nonce, ad, pt) == ctt
    ct, tag = ctt[:-16], ctt[-16:]
    out.append((len(ad) << 16) | len(pt))
    out += words(key) + words(nonce)
    if ad:
        out += words(blocks(ad))
    out += words(blocks(pt)) + words(blocks(ct)) + words(tag)
    count += 1
out.append(0xFFFFFFFF)

with open(out_path, "w") as f:
    f.write("\n".join("%08x" % w for w in out) + "\n")
print(f"{count} vectors, {len(out)} words -> {out_path}")
