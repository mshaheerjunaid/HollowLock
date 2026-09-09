# iana tls supported-group codepoints we care about
# https://www.iana.org/assignments/tls-parameters

# post-quantum hybrids. 0x11ec is the standardised one everyone is moving to;
# 0x6399 is the older draft cloudflare/chrome shipped before standardisation.
PQ_GROUPS = {
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
}

# plain classical groups, still what most of the internet uses
CLASSICAL_GROUPS = {
    0x001D: "X25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
}

ALL_NAMES = {**PQ_GROUPS, **CLASSICAL_GROUPS}


def name_of(code):
    # fall back to hex so an unknown group still prints something useful
    return ALL_NAMES.get(code, f"0x{code:04x}")


def is_pq(code):
    return code in PQ_GROUPS
