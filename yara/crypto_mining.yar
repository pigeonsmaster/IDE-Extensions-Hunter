rule CryptoMining {
    meta:
        description = "Detects potential cryptocurrency mining code"
        severity = 3
        category = "malware"
        author = "IDE Extension Hunter"
        date = "2024-04-26"

    strings:
        $mining_keywords = /mining|hashrate|difficulty|blockchain|web3|ethereum|bitcoin|cryptocurrency/i
        $mining_functions = /mine|hash|proofOfWork|getWork|submitWork|getHashrate/i
        $suspicious_apis = /coinhive|webminer|coin-hive|coinhive.com|webminerpool|minergate/i
        $crypto_wallets = /0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71}/i

    condition:
        any of ($mining_keywords) and
        (
            2 of ($mining_functions) or
            any of ($suspicious_apis) or
            any of ($crypto_wallets)
        )
} 