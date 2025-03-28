const fs = require('fs');

// Function to load JSON data from a file
function loadData(fileName) {
    return JSON.parse(fs.readFileSync(fileName, 'utf-8'));
}

// Password Strength Checker
function checkPasswordStrength(password) {
    let strength = 0;
    const recommendations = [];

    // Check length
    if (password.length < 8) {
        recommendations.push("Use at least 8 characters");
    } else if (password.length >= 12) {
        strength += 30;
    } else {
        strength += 20;
    }

    // Check character types
    if (/[A-Z]/.test(password)) strength += 20;
    else recommendations.push("Add uppercase letters");

    if (/[a-z]/.test(password)) strength += 20;
    else recommendations.push("Add lowercase letters");

    if (/[0-9]/.test(password)) strength += 20;
    else recommendations.push("Add numbers");

    if (/[^A-Za-z0-9]/.test(password)) strength += 20;
    else recommendations.push("Add special characters");

    // Calculate time to crack (simplified estimation)
    const charsetSize = calculateCharsetSize(password);
    const attemptsPerSecond = 1000000000; // 1 billion attempts per second
    const possibleCombinations = Math.pow(charsetSize, password.length);
    const secondsToCrack = possibleCombinations / attemptsPerSecond;

    let timeText;
    if (secondsToCrack < 60) {
        timeText = `${secondsToCrack.toFixed(2)} seconds`;
    } else if (secondsToCrack < 3600) {
        timeText = `${(secondsToCrack / 60).toFixed(2)} minutes`;
    } else if (secondsToCrack < 86400) {
        timeText = `${(secondsToCrack / 3600).toFixed(2)} hours`;
    } else if (secondsToCrack < 31536000) {
        timeText = `${(secondsToCrack / 86400).toFixed(2)} days`;
    } else {
        timeText = `${(secondsToCrack / 31536000).toFixed(2)} years`;
    }

    // Determine strength level
    let strengthText;
    let color;
    if (strength <= 40) {
        strengthText = "Weak";
        color = "#ff4d4d";
    } else if (strength <= 70) {
        strengthText = "Moderate";
        color = "#ffa500";
    } else {
        strengthText = "Strong";
        color = "#00cc00";
    }

    return {
        strength,
        strengthText,
        timeText,
        recommendations,
        color,
    };
}

// Helper function to calculate the charset size
function calculateCharsetSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/[0-9]/.test(password)) size += 10;
    if (/[^A-Za-z0-9]/.test(password)) size += 32;
    return size;
}

// Phishing Link Risk Calculator
function calculateRisk(url) {
    const whitelistedDomains = loadData('whitelistedDomains.json');
    const suspiciousDomains = loadData('suspiciousDomains.json');
    const suspiciousKeywords = loadData('suspiciousKeywords.json');
    const blockedDomains = loadData('blockedDomains.json');
    let risk = 0;
    let reasons = [];
    const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    let domain = parsed.hostname.toLowerCase().replace(/^www\./, '');
    const fullUrl = (domain + parsed.pathname + parsed.search).toLowerCase();

    if (parsed.protocol === 'http:') {
        risk += 40;
        reasons.push("Uses HTTP instead of HTTPS (less secure).");
    }

    if (!whitelistedDomains.includes(domain)) {
        risk += 20;
        reasons.push("Domain is not in the trusted whitelist.");
    }

    suspiciousKeywords.forEach(keyword => {
        if (fullUrl.includes(keyword)) {
            risk += 30;
            reasons.push(`Contains suspicious keyword: '${keyword}'.`);
        }
    });

    suspiciousDomains.forEach(suspicious => {
        if (domain.endsWith(suspicious)) {
            risk += 30;
            reasons.push(`Domain has a suspicious extension: '${suspicious}'.`);
        }
    });

    if (blockedDomains.includes(domain)) {
        risk += 100;
        reasons.push(`Domain is explicitly BLOCKED (${domain}).`);
    }

    let safetyMessage = '';
    if (risk === 0) {
        safetyMessage = "This URL appears to be safe!";
    } else if (risk <= 50) {
        safetyMessage = "Risk level: Low. Proceed with caution.";
    } else if (risk <= 100) {
        safetyMessage = "Risk level: Medium. Be cautious when interacting with this URL.";
    } else {
        safetyMessage = "Risk level: High. This URL is highly suspicious, do not interact with it!";
    }

    return {
        risk,
        safetyMessage,
        reasons,
    };
}

// Password Generator
function generatePassword(passwordLength = 12, includeNumbers = true, includeSpecial = true) {
    const lowerCase = 'abcdefghijklmnopqrstuvwxyz';
    const upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let charSet = lowerCase + upperCase;
    if (includeNumbers) charSet += numbers;
    if (includeSpecial) charSet += specialChars;

    let password = '';
    for (let i = 0; i < passwordLength; i++) {
        password += charSet[Math.floor(Math.random() * charSet.length)];
    }

    return password;
}

