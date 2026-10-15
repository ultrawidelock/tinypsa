#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Turns the fetched CAVP and Wycheproof files into C tables (see vectors.h).

Usage: gen_vectors.py <vectors dir> <out.c> [byte budget]

With a budget, each table keeps an evenly spaced sample so the hex strings of
all tables together fit in about that many bytes (for on-target runs).

Only the P-256 / SHA-256 / AES slices tinypsa implements are kept. Inputs are
downloaded files: they are parsed as data and never executed.
"""
import json
import os
import sys

VEC, OUT = sys.argv[1], sys.argv[2]
BUDGET = int(sys.argv[3]) if len(sys.argv) > 3 else 0


def path(*p):
    return os.path.join(VEC, *p)


def rsp(name):
    """Yields (section, record) from a CAVP response file.

    Bracketed headers set section values; a block without Count, COUNT or Msg (the
    Key line in CCM DVPT files) sets section values too.
    """
    sect, rec = {}, {}

    def flush():
        nonlocal rec
        if rec:
            if any(k in rec for k in ("Count", "COUNT", "Msg")):
                yield dict(sect), rec
            else:
                sect.update(rec)
        rec = {}

    for line in open(name, errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            yield from flush()
            continue
        if line.startswith("["):
            yield from flush()
            inner = line.strip("[]")
            if "=" in inner:
                for part in inner.split(","):
                    k, v = part.split("=", 1)
                    sect[k.strip()] = v.strip()
            else:
                sect["name"] = inner
            continue
        if line == "FAIL":
            rec["FAIL"] = True
        elif "=" in line:
            k, v = (s.strip() for s in line.split("=", 1))
            if k in rec:
                rec[k] = rec[k] + "," + v
            else:
                rec[k] = v
    yield from flush()


def cut(h, nbytes):
    return h[: 2 * nbytes]


tables = {k: [] for k in
          ("sha256", "macs", "ecbs", "aeads", "ecdsas", "siggens", "ecdhs", "hkdfs", "drbgs")}


def wyche_expect(t):
    return {"valid": 1, "invalid": 0, "acceptable": -1}[t["result"]]


# ---- CAVP -----------------------------------------------------------------
sha = path("cavp", "shabytetestvectors", "shabytetestvectors")
for f in ("SHA256ShortMsg.rsp", "SHA256LongMsg.rsp"):
    rec = {}
    for line in open(os.path.join(sha, f)):
        line = line.strip()
        if "=" not in line or line.startswith("["):
            continue
        k, v = (s.strip() for s in line.split("=", 1))
        rec[k] = v
        if k == "MD":
            n = int(rec["Len"]) // 8
            tables["sha256"].append((f"cavp {f} len {rec['Len']}", cut(rec["Msg"], n), v))
            rec = {}

for s, r in rsp(path("cavp", "hmactestvectors", "HMAC.rsp")):
    if s.get("L") == "32":
        tables["macs"].append((f"cavp HMAC L=32 #{r['Count']}", 0, r["Key"],
                               r["Msg"], cut(r["Mac"], int(r["Tlen"])), 1))

for bits in ("128", "256"):
    for s, r in rsp(path("cavp", "cmactestvectors", f"CMACGenAES{bits}.rsp")):
        msg = cut(r["Msg"], int(r["Mlen"]))
        tables["macs"].append((f"cavp CMACGenAES{bits} #{r['Count']}", 1, r["Key"], msg,
                               cut(r["Mac"], int(r["Tlen"])), 1))

for kind in ("GFSbox", "KeySbox", "VarKey", "VarTxt"):
    for bits in ("128", "256"):
        for s, r in rsp(path("cavp", "KAT_AES", f"ECB{kind}{bits}.rsp")):
            if s.get("name") == "ENCRYPT":
                tables["ecbs"].append((f"cavp ECB{kind}{bits} #{r['COUNT']}", r["KEY"],
                                       r["PLAINTEXT"], r["CIPHERTEXT"]))

for bits in ("128", "256"):
    for s, r in rsp(path("cavp", "ccmtestvectors", f"DVPT{bits}.rsp")):
        alen, plen, tlen = int(s["Alen"]), int(s["Plen"]), int(s["Tlen"])
        ct = r["CT"]
        ok = r["Result"].startswith("Pass")
        pt = cut(r.get("Payload", ""), plen) if ok else ""
        tables["aeads"].append((f"cavp DVPT{bits} {s['Alen']}/{s['Plen']}/{s['Nlen']}/{s['Tlen']} #{r['Count']}",
                                1, s["Key"], r["Nonce"], cut(r["Adata"], alen), pt,
                                ct[: 2 * plen], ct[2 * plen:], 1 if ok else 0))

for bits in ("128", "256"):
    for f, dec in ((f"gcmEncryptExtIV{bits}.rsp", False), (f"gcmDecrypt{bits}.rsp", True)):
        for s, r in rsp(path("cavp", "gcmtestvectors", f)):
            fail = r.get("FAIL", False)
            tables["aeads"].append((f"cavp {f} {s['IVlen']}/{s['PTlen']}/{s['AADlen']}/{s['Taglen']} #{r['Count']}",
                                    0, r["Key"], r["IV"], r["AAD"],
                                    "" if fail else r["PT"], r["CT"], r["Tag"], 0 if fail else 1))

ecdsa = path("cavp", "186-4ecdsatestvectors", "186-4ecdsatestvectors")
for s, r in rsp(os.path.join(ecdsa, "SigVer.rsp")):
    if s.get("name") == "P-256,SHA-256":
        pub = "04" + r["Qx"].zfill(64) + r["Qy"].zfill(64)
        tables["ecdsas"].append((f"cavp SigVer P-256 #{len(tables['ecdsas'])}", pub, r["Msg"],
                                 r["R"].zfill(64) + r["S"].zfill(64),
                                 1 if r["Result"].startswith("P") else 0))
# SigGen.txt has no Count lines; collect by hand.
sect, rec = None, {}
for line in open(os.path.join(ecdsa, "SigGen.txt"), errors="replace"):
    line = line.strip()
    if line.startswith("["):
        sect = line.strip("[]")
        continue
    if "=" in line and not line.startswith("#"):
        k, v = (x.strip() for x in line.split("=", 1))
        rec[k] = v
        if k == "S":
            if sect == "P-256,SHA-256":
                tables["siggens"].append((f"cavp SigGen P-256 #{len(tables['siggens'])}",
                                          rec["d"].zfill(64), rec["Msg"], rec["k"].zfill(64),
                                          rec["R"].zfill(64), rec["S"].zfill(64)))
            rec = {}

for s, r in rsp(path("cavp", "ecccdhtestvectors", "KAS_ECC_CDH_PrimitiveTest.txt")):
    if s.get("name") == "P-256":
        tables["ecdhs"].append((f"cavp CDH P-256 #{r['COUNT']}", r["dIUT"].zfill(64),
                                "04" + r["QCAVSx"].zfill(64) + r["QCAVSy"].zfill(64),
                                r["ZIUT"].zfill(64), 1))

for sub in ("drbgvectors_no_reseed", "drbgvectors_pr_false"):
    for s, r in rsp(path("cavp", "drbgtestvectors", sub, "HMAC_DRBG.rsp")):
        if s.get("name") != "SHA-256" or s.get("PredictionResistance") != "False":
            continue
        adds = [v for k, v in r.items() if k.startswith("AdditionalInput")]
        if any(x.replace(",", "") for x in adds):
            continue
        tables["drbgs"].append((f"cavp {sub} pers {s['PersonalizationStringLen']} #{r['COUNT']}",
                                r["EntropyInput"], r["Nonce"], r["PersonalizationString"],
                                r.get("EntropyInputReseed", ""), r["ReturnedBits"]))

# ---- Wycheproof -------------------------------------------------------------
def wyche(name):
    d = json.load(open(path("wycheproof", name)))
    for g in d["testGroups"]:
        for t in g["tests"]:
            yield g, t


for name, ccm in (("aes_gcm_test.json", 0), ("aes_ccm_test.json", 1)):
    for g, t in wyche(name):
        tables["aeads"].append((f"wycheproof {name} tc {t['tcId']}", ccm, t["key"], t["iv"],
                                t["aad"], t["msg"], t["ct"], t["tag"], wyche_expect(t)))

for name, cmac in (("hmac_sha256_test.json", 0), ("aes_cmac_test.json", 1)):
    for g, t in wyche(name):
        tables["macs"].append((f"wycheproof {name} tc {t['tcId']}", cmac, t["key"], t["msg"],
                               t["tag"], wyche_expect(t)))

for g, t in wyche("ecdsa_secp256r1_sha256_p1363_test.json"):
    tables["ecdsas"].append((f"wycheproof p1363 tc {t['tcId']}", g["publicKey"]["uncompressed"],
                             t["msg"], t["sig"], wyche_expect(t)))

for g, t in wyche("ecdh_secp256r1_ecpoint_test.json"):
    tables["ecdhs"].append((f"wycheproof ecdh tc {t['tcId']}", t["private"], t["public"],
                            t["shared"], wyche_expect(t)))

for g, t in wyche("hkdf_sha256_test.json"):
    tables["hkdfs"].append((f"wycheproof hkdf tc {t['tcId']}", t["ikm"], t["salt"], t["info"],
                            t["okm"], t["size"], wyche_expect(t)))

# ---- emit -------------------------------------------------------------------
TYPES = {"sha256": ("vec_hash", "vec_sha256"), "macs": ("vec_mac", "vec_macs"),
         "ecbs": ("vec_ecb", "vec_ecbs"), "aeads": ("vec_aead", "vec_aeads"),
         "ecdsas": ("vec_ecdsa", "vec_ecdsas"), "siggens": ("vec_siggen", "vec_siggens"),
         "ecdhs": ("vec_ecdh", "vec_ecdhs"), "hkdfs": ("vec_hkdf", "vec_hkdfs"),
         "drbgs": ("vec_drbg", "vec_drbgs")}


def lit(v):
    if isinstance(v, int):
        return str(v)
    assert all(c.isalnum() or c in " #/._-=," for c in v), v[:40]
    return '"' + v + '"'


def size(row):
    return sum(len(v) for v in row if isinstance(v, str))


if BUDGET:
    # Tables under an even share keep everything; the rest split what is left.
    left, big = BUDGET, sorted(tables, key=lambda k: sum(size(r) for r in tables[k]))
    while big:
        key, share = big.pop(0), left // (len(big) + 1)
        total = sum(size(r) for r in tables[key])
        stride = -(-total // share) if total > share else 1
        tables[key] = tables[key][::stride]
        left -= sum(size(r) for r in tables[key])

with open(OUT, "w") as o:
    o.write("/* Generated by gen_vectors.py. Do not edit. */\n#include \"vectors.h\"\n\n")
    for key, (typ, name) in TYPES.items():
        rows = tables[key]
        o.write(f"const struct {typ} {name}[] = {{\n")
        for row in rows:
            o.write("\t{ " + ", ".join(lit(v) for v in row) + " },\n")
        o.write(f"}};\nconst size_t {name}_count = {len(rows)};\n\n")
print(" ".join(f"{k}={len(v)}" for k, v in tables.items()),
      f"bytes={sum(size(r) for v in tables.values() for r in v)}")
