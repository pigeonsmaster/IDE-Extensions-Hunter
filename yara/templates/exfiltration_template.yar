/*
 * Data Exfiltration Detection Template
 * Use this template to detect data being sent to external servers
 */

rule Exfiltration_RULE_NAME {
    meta:
        description = "Detects data exfiltration to [service/method]"
        severity = 4
        category = "exfiltration"
        author = "Your Name"
        date = "2025-11-19"

    strings:
        // Destination indicators
        $service_url = "service.com"
        $webhook = "webhook"

        // HTTP methods
        $fetch = "fetch("
        $axios = "axios"
        $http_request = "http.request"
        $post = "POST" nocase

        // Data collection
        $readFile = "readFileSync"
        $env = "process.env"
        $cookie = "document.cookie"

    condition:
        // Service URL + HTTP method + data collection
        any of ($service_url, $webhook) and
        any of ($fetch, $axios, $http_request, $post) and
        any of ($readFile, $env, $cookie)
}
