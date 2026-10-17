# iana tls supported-group codepoints we care about
# https://www.iana.org/assignments/tls-parameters

STANDARD_HYBRID = "standard hybrid"
PURE_MLKEM = "pure ML-KEM"
LEGACY_DRAFT = "legacy draft"
CLASSICAL = "classical"

# code -> (name, kind)
GROUPS = {
    0x11EC: ("X25519MLKEM768", STANDARD_HYBRID),
    0x11EB: ("SecP256r1MLKEM768", STANDARD_HYBRID),
    0x11ED: ("SecP384r1MLKEM1024", STANDARD_HYBRID),
    0x0200: ("MLKEM512", PURE_MLKEM),
    0x0201: ("MLKEM768", PURE_MLKEM),
    0x0202: ("MLKEM1024", PURE_MLKEM),
    # kyber drafts chrome and cloudflare shipped before ml-kem was final
    0x6399: ("X25519Kyber768Draft00", LEGACY_DRAFT),
    0x639A: ("SecP256r1Kyber768Draft00", LEGACY_DRAFT),
    0x001D: ("X25519", CLASSICAL),
    0x0017: ("secp256r1", CLASSICAL),
    0x0018: ("secp384r1", CLASSICAL),
    0x0019: ("secp521r1", CLASSICAL),
    0x0100: ("ffdhe2048", CLASSICAL),
    0x0101: ("ffdhe3072", CLASSICAL),
}


def name_of(code):
    if code is None:
        return None
    return GROUPS[code][0] if code in GROUPS else f"0x{code:04x}"


def kind_of(code):
    # anything we don't know is treated as classical, it can't be counted as pq
    return GROUPS[code][1] if code in GROUPS else CLASSICAL


def is_pq(code):
    return code is not None and kind_of(code) != CLASSICAL


def is_standard_hybrid(code):
    return code is not None and kind_of(code) == STANDARD_HYBRID


def is_pure_mlkem(code):
    return code is not None and kind_of(code) == PURE_MLKEM


def is_legacy_draft(code):
    return code is not None and kind_of(code) == LEGACY_DRAFT
