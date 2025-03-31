# Phishing API

## Overview
Phishing API is a tool designed to analyze URLs and assess their risk of being associated with phishing attacks. It provides various checks, including domain age, DNS resolution, suspicious keywords, and more, to identify potentially harmful links.

This API can be used to enhance the security of your application by evaluating links that users may click on and alerting them to any risks associated with those URLs. The API also provides password strength validation and a password generator feature.

## Features
- **URL Risk Calculation:** Analyzes a URL for various risk factors like suspicious keywords, DNS resolution issues, domain age, and more.
- **Password Strength Checker:** Evaluates the strength of a password based on length, character variety, and time-to-crack estimates.
- **Password Generator:** Generates a strong, random password based on user-defined parameters like length and inclusion of numbers or special characters.
- **Domain Age & DNS Check:** Checks the age of a domain and whether the domain resolves correctly via DNS.
- **Whitelist, Blocklist, Suspicious Domains & Keywords:** Allows configuration of whitelisted, blocked, and suspicious domains or keywords to enhance the security checks.

## Meta Data Extraction (Important Note)
The **Meta Data Extraction** feature is designed for **deep threat protection**. It scrapes the content of a URL to search for suspicious keywords and signs of obfuscation (such as encoded characters or unusual patterns).

However, **please note that enabling Meta Data Extraction may slow down production performance** because it requires additional requests to external services and deeper analysis of the webpage content. If you need fast performance and only basic checks, **disable this feature** in production environments.

### When to Use Meta Data Extraction:
- **Enhanced Security:** If you're running a high-security application where every detail matters and you need to scrutinize every aspect of the webpage content.
- **Deep Threat Protection:** If you're aiming for a more comprehensive analysis of potentially dangerous links and want to account for obfuscation or suspicious content on the site.

### When to Avoid Meta Data Extraction:
- **Production Environments:** If you're running a production environment where speed and efficiency are paramount, and basic checks are sufficient, disabling this feature will improve performance.
- **Less Intensive Security Needs:** If you don't need the most detailed analysis and just want basic phishing risk checks (domain age, DNS resolution, and whitelisting/blacklisting).

## Configuration
You can configure the API by modifying the `config.json` file located in the `PhishingAuthorityData` folder. The configuration file allows you to enable or disable different checks like:
- API checks
- Whitelist usage
- Suspicious domain and keyword checks
- Domain age and DNS checks
- Meta data extraction (for deep threat protection)

Example `config.json` (most optimised):
```json
{
    "enableAPI": true,
    "useWhitelist": true,
    "useSuspiciousDomains": true,
    "useSuspiciousKeywords": true,
    "useBlockedDomains": true,
    "useDNSResolve": true,
    "useDomainAgeCheck": true,
    "useDnsProviderCheck": true,
    "useEncodedCharsCheck": true,
    "useMetaData": false,
    "riskWeights": {
        "http": 40,
        "notWhitelisted": 20,
        "suspiciousKeyword": 30,
        "suspiciousDomain": 30,
        "blockedDomain": 100
    }
}
