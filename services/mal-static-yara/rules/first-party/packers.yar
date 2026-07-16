// First-party OpenMalLab rules. License: Apache-2.0 (same as the core).
// Module-free on purpose: they match raw bytes so they run without the pe
// module and stay robust across yara-x versions. Each rule is self-describing
// via meta (verdict + attck), which the worker reads instead of hardcoding.
//
// A packer is not malware by itself, but packed code is unanalyzed code, so a
// packed verdict is SUSPICIOUS, not MALICIOUS: it tells the pipeline "the real
// payload is hidden here, do not trust a benign static read."

rule packer_upx {
    meta:
        description = "UPX-packed executable (UPX section markers present)"
        attck = "T1027.002"
        verdict = "SUSPICIOUS"
        license = "Apache-2.0"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upxbang = "UPX!"
    condition:
        // two of the three markers keeps benign strings that merely contain
        // "UPX" from matching.
        2 of them
}

rule packer_high_entropy_hint_aspack {
    meta:
        description = "ASPack-packed executable (ASPack section marker)"
        attck = "T1027.002"
        verdict = "SUSPICIOUS"
        license = "Apache-2.0"
    strings:
        $aspack = ".aspack"
        $adata = ".adata"
    condition:
        any of them
}
