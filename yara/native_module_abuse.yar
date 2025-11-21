/*
 * Native Module Abuse Detection Rules
 * Detects suspicious native module usage
 */

rule Native_Module_With_Network {
    meta:
        description = "Native .node module with network capabilities"
        severity = 3
        category = "native_abuse"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $node_ext = ".node"
        $require = "require("

        $net = "require('net')"
        $http = "require('http')"
        $https = "require('https')"
        $child_process = "require('child_process')"

    condition:
        $node_ext and $require and
        any of ($net, $http, $https, $child_process)
}

rule Child_Process_Suspicious_Commands {
    meta:
        description = "Child process with suspicious commands"
        severity = 3
        category = "native_abuse"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $child_process = "child_process"
        $exec = ".exec("
        $spawn = ".spawn("

        $curl = "curl"
        $wget = "wget"
        $netcat = "netcat"
        $bash = "bash"
        $sh = "/bin/sh"
        $powershell = "powershell"
        $chmod = "chmod"

    condition:
        $child_process and ($exec or $spawn) and
        any of ($curl, $wget, $netcat, $bash, $sh, $powershell, $chmod)
}

rule WASM_Module_Execution {
    meta:
        description = "WebAssembly module execution"
        severity = 2
        category = "native_abuse"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $wasm_instantiate = "WebAssembly.instantiate"
        $wasm_compile = "WebAssembly.compile"

        $readFile = "readFileSync"
        $fetch = "fetch"

    condition:
        ($wasm_instantiate or $wasm_compile) and
        ($readFile or $fetch)
}

rule Process_Fork_With_Execution {
    meta:
        description = "Process fork with execution capabilities"
        severity = 3
        category = "native_abuse"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $fork = ".fork("
        $cluster = "require('cluster')"

        $exec = "exec"
        $execve = "execve"
        $system = "system("
        $spawn = "spawn"

    condition:
        ($fork or $cluster) and any of ($exec, $execve, $system, $spawn)
}
