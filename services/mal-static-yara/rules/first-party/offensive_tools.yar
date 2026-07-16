// First-party OpenMalLab rules for well-known offensive tooling. License:
// Apache-2.0. Matching these tool-signature strings is safe (they are just
// strings, not the tools themselves) and high-signal on a submitted artifact.

rule tool_mimikatz {
    meta:
        description = "Mimikatz credential-dumping tool artifacts"
        attck = "T1003.001"
        verdict = "MALICIOUS"
        license = "Apache-2.0"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "Invoke-Mimikatz" nocase
        $c = "gentilkiwi" nocase
        $d = "mimikatz" nocase
    condition:
        any of them
}

rule tool_cobaltstrike_beacon_hints {
    meta:
        description = "Cobalt Strike beacon configuration hints"
        attck = "T1071.001"
        verdict = "MALICIOUS"
        license = "Apache-2.0"
    strings:
        // benign-safe marker strings associated with default beacon profiles.
        $a = "beacon.dll" nocase
        $b = "beacon.x64.dll" nocase
        $c = "%%IMPORT%%"
        $d = "ReflectiveLoader"
    condition:
        2 of them
}
