// First-party OpenMalLab webshell rules. License: Apache-2.0.
// These match the superglobal-into-eval idiom that defines a webshell, not the
// bare eval() that appears in plenty of legitimate code.

rule webshell_php_eval_superglobal {
    meta:
        description = "PHP webshell: eval/assert/system on a request superglobal"
        attck = "T1505.003"
        verdict = "MALICIOUS"
        license = "Apache-2.0"
    strings:
        $e1 = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $e2 = /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $e3 = /system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $e4 = /passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
    condition:
        any of them
}

rule webshell_asp_eval_request {
    meta:
        description = "Classic ASP webshell: eval/execute on Request"
        attck = "T1505.003"
        verdict = "MALICIOUS"
        license = "Apache-2.0"
    strings:
        $a = /eval\s+request\s*\(/ nocase
        $b = /execute\s+request\s*\(/ nocase
        $c = "eval(Request." nocase
    condition:
        any of them
}
