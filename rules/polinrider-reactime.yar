/*
   YARA rules - PolinRider / NullReceiver (Reactime compromise, Windows variant)
   Deep Woods Security. Detection for the loader, the Electron-injection module,
   and the injected VS Code / Discord entry points.
*/

rule PolinRider_Loader_FakeFont
{
    meta:
        description = "PolinRider stage-1 loader disguised as a web font (fa-solid-900.woff2 / babel.config.js variant)"
        reference   = "https://github.com/open-source-labs/Reactime/issues/368"
        author      = "Deep Woods Security"
    strings:
        $tag1 = "9-0476-3"  ascii
        $tag2 = "A9-0476-3" ascii
        $g1   = "global['!']" ascii
        $g2   = "global['_V']" ascii
    condition:
        2 of them
}

rule PolinRider_Inject_Module
{
    meta:
        description = "PolinRider Electron-injection backdoor module (self-labeled app-vscode-eval / app-discord-eval)"
        author      = "Deep Woods Security"
        hash        = "42ff8df9907110ef87aa15876215f77a3862c42f94d71070a0f16ee1b7a7d223"
    strings:
        $l1 = "app-vscode-eval"  ascii
        $l2 = "app-discord-eval" ascii
        $m1 = "RS260605" ascii
        $m2 = "M260630A" ascii
        $t  = "A9-0476-3" ascii
        // golden-ratio PRNG constant used by the string stream cipher
        $gr = "2654435769" ascii
    condition:
        (1 of ($l*)) and (1 of ($m*) or $t)
}

rule PolinRider_Inject_Site_VSCode
{
    meta:
        description = "PolinRider injection marker prepended to VS Code main.js"
        author      = "Deep Woods Security"
    strings:
        $a = "createRequire as __inzCR" ascii
        $b = "__inzCR(import.meta.url)(\"./main.inz.cjs\")" ascii
        $c = "const __inzV=" ascii
        $m = "M260630A" ascii
    condition:
        $b or ($a and $c) or ($a and $m)
}

rule PolinRider_C2_Beacon_Strings
{
    meta:
        description = "PolinRider C2 beacon/exfil artifacts (endpoints, header, tag)"
        author      = "Deep Woods Security"
    strings:
        $h  = "Sec-V: A9-0476-3" ascii
        $e1 = "/verify-human/A9-0476-3" ascii
        $e2 = "/u/f" ascii
        $e3 = "/u/e3" ascii
        $ip = "193.247.144.38" ascii
    condition:
        $h or $e1 or $ip or (2 of ($e*))
}
