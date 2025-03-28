**PhishingAuthority-API**

This repository contains a set of security-related utility functions to help you manage passwords and assess URL safety. The features include:

Password Strength Checker: Evaluates password strength based on length, character diversity (uppercase, lowercase, numbers, special characters), and estimates how long it would take for a brute-force attack to crack the password.

Phishing Link Risk Calculator: Analyzes URLs for potential phishing or malicious threats. It checks for unsafe protocols (HTTP), verifies domains against whitelists, suspicious domains, and blocked domains, and looks for keywords or suspicious extensions that could indicate a phishing attempt.

Password Generator: Generates random, secure passwords with customizable length, and options to include numbers and special characters.

**Features**
Password strength analysis with clear recommendations.

Phishing link risk assessment based on URL components.

Password generation with customizable complexity.

**Requirements**
Node.js for running the code.

JSON files for whitelistedDomains, suspiciousDomains, suspiciousKeywords, and blockedDomains for phishing risk calculation.

**Usage**
Check password strength and get recommendations.

Analyze URLs for phishing risk.

Generate random, secure passwords.

**Note:**
This repository is provided as-is. You must supply your own JSON data files for the phishing risk calculation functions to work properly.
