/*
 * Data Exfiltration Detection Rules
 * Detects data being sent to external servers
 */

rule Discord_Webhook_Exfiltration {
    meta:
        description = "Sends data to Discord webhook"
        severity = 4
        category = "exfiltration"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $discord1 = "discord.com/api/webhooks/"
        $discord2 = "discordapp.com/api/webhooks/"

        $post = "POST" nocase
        $fetch = "fetch("
        $axios = "axios"

    condition:
        any of ($discord*) and ($post or $fetch or $axios)
}

rule Telegram_Bot_Exfiltration {
    meta:
        description = "Sends data via Telegram Bot API"
        severity = 4
        category = "exfiltration"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $telegram_api = "api.telegram.org/bot"
        $sendMessage = "sendMessage"
        $sendDocument = "sendDocument"

        $fetch = "fetch("
        $axios = "axios"
        $http = "http.request"

    condition:
        $telegram_api and
        ($sendMessage or $sendDocument) and
        any of ($fetch, $axios, $http)
}

rule File_Upload_To_Server {
    meta:
        description = "Uploads files to external server"
        severity = 3
        category = "exfiltration"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $readFileSync = "readFileSync"
        $readFile = "readFile("
        $createReadStream = "createReadStream"

        $post = "POST" nocase
        $formData = "FormData"
        $multipart = "multipart/form-data"

        $fetch = "fetch("
        $axios = "axios"

    condition:
        any of ($readFileSync, $readFile, $createReadStream) and
        ($post or $formData or $multipart) and
        any of ($fetch, $axios)
}

rule Pastebin_Service_Upload {
    meta:
        description = "Uploads data to pastebin-like services"
        severity = 3
        category = "exfiltration"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $pastebin = "pastebin.com"
        $hastebin = "hastebin.com"
        $ghostbin = "ghostbin.com"

        $post = "POST"
        $fetch = "fetch("

    condition:
        any of ($pastebin, $hastebin, $ghostbin) and ($post or $fetch)
}

rule Cloud_Storage_Upload {
    meta:
        description = "Uploads to cloud storage services"
        severity = 3
        category = "exfiltration"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $aws_s3 = "aws-sdk" nocase
        $s3 = "s3" nocase
        $google_storage = "google-cloud/storage"
        $azure_storage = "azure-storage"

        $upload = ".upload("
        $putObject = "putObject"

        $readFile = "readFileSync"

    condition:
        (($aws_s3 and $s3) or $google_storage or $azure_storage) and
        ($upload or $putObject) and $readFile
}
