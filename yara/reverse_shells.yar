/*
 * Reverse Shell and C2 Detection Rules
 * Detects command and control patterns
 */

rule Bash_Reverse_Shell {
    meta:
        description = "Bash TCP reverse shell pattern"
        severity = 4
        category = "c2"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $dev_tcp = "/dev/tcp/"
        $bash_i = "bash -i"
        $sh_i = "sh -i"

        $exec = "exec("
        $spawn = "spawn("
        $child_process = "child_process"

    condition:
        $dev_tcp and (any of ($bash_i, $sh_i, $exec, $spawn) or $child_process)
}

rule WebSocket_C2_Channel {
    meta:
        description = "WebSocket used for C2 communication"
        severity = 4
        category = "c2"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $websocket = "new WebSocket("
        $wss = "wss://"
        $ws = "ws://"

        $onmessage = ".onmessage"

        $eval = "eval("
        $exec = "exec("
        $function = "new Function("

    condition:
        $websocket and ($wss or $ws) and $onmessage and
        any of ($eval, $exec, $function)
}

rule HTTP_C2_Beacon {
    meta:
        description = "Regular HTTP beaconing pattern"
        severity = 3
        category = "c2"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $setInterval = "setInterval("
        $setTimeout = "setTimeout("

        $fetch = "fetch("
        $axios = "axios"
        $http_request = "http.request"

        $eval = "eval("

    condition:
        ($setInterval or $setTimeout) and
        any of ($fetch, $axios, $http_request) and
        $eval
}

rule Node_Net_Socket_Connection {
    meta:
        description = "Node.js net.Socket reverse connection"
        severity = 4
        category = "c2"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $net_require = "require('net')"
        $net_socket = "net.Socket"
        $connect = ".connect("

        $child_process = "child_process"
        $spawn = ".spawn("
        $shell = "/bin/sh"

    condition:
        ($net_require or $net_socket) and $connect and
        ($child_process or $spawn or $shell)
}

rule Netcat_Reverse_Shell {
    meta:
        description = "Netcat-based reverse shell"
        severity = 4
        category = "c2"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $nc = "nc -e"
        $netcat = "netcat -e"
        $ncat = "ncat -e"

        $exec = "exec("
        $spawn = "spawn("

    condition:
        any of ($nc, $netcat, $ncat) and any of ($exec, $spawn)
}
