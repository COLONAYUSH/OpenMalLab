// First-party OpenMalLab rules for scripting-language attack patterns.
// License: Apache-2.0. These target specific attacker idioms, not generic
// language features, to keep false positives off legitimate code.

rule powershell_download_cradle {
    meta:
        description = "PowerShell download-and-execute cradle (IEX + web client)"
        attck = "T1059.001"
        verdict = "MALICIOUS"
        license = "Apache-2.0"
    strings:
        // the classic one-liner; requires both the exec and the fetch so a
        // benign script that merely downloads a file does not match.
        $iex = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl = "DownloadString" nocase
        $dl2 = "DownloadData" nocase
        $wc = "Net.WebClient" nocase
    condition:
        (any of ($iex*)) and (any of ($dl*)) and $wc
}

rule powershell_encoded_command {
    meta:
        description = "PowerShell executing a base64 -EncodedCommand payload"
        attck = "T1027"
        verdict = "SUSPICIOUS"
        license = "Apache-2.0"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "FromBase64String" nocase
        $ps = "powershell" nocase
    condition:
        $ps and any of ($enc*)
}

rule shell_reverse_tcp_bash {
    meta:
        description = "Bash reverse shell over /dev/tcp"
        attck = "T1059.004"
        verdict = "MALICIOUS"
        license = "Apache-2.0"
    strings:
        $a = "/dev/tcp/"
        $b = "bash -i" nocase
        $c = "sh -i" nocase
    condition:
        $a and ($b or $c)
}
