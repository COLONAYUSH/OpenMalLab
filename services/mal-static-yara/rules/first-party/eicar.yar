rule eicar_test_file {
    meta:
        description = "EICAR standard antivirus test string. it is a benign test file, used here as a safe stand-in for a known-bad signature hit so we can prove the pipeline without live malware."
        attck = "T1204"
        verdict = "MALICIOUS"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
