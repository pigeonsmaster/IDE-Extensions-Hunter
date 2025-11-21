/*
 * Command and Control Detection Template
 * Use this template to detect C2 communication patterns
 */

rule C2_RULE_NAME {
    meta:
        description = "Detects [C2 method/technique]"
        severity = 4
        category = "c2"
        author = "Your Name"
        date = "2025-11-19"

    strings:
        // Communication channels
        $websocket = "new WebSocket("
        $net_socket = "net.Socket"
        $http_server = "http.createServer"

        // Suspicious patterns
        $dev_tcp = "/dev/tcp/"
        $reverse_shell = "bash -i"

        // Code execution
        $eval = "eval("
        $exec = "exec("
        $spawn = "spawn("

        // Beaconing indicators
        $setInterval = "setInterval("
        $setTimeout = "setTimeout("

    condition:
        // Communication + execution
        any of ($websocket, $net_socket, $http_server, $dev_tcp) and
        any of ($eval, $exec, $spawn)
        or
        // Beaconing pattern
        ($setInterval or $setTimeout) and $eval
}
