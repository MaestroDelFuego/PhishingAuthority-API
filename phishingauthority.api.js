const fs = require('fs');
const dns = require('dns'); // To check for domain details and verify valid domains
const whois = require('whois'); // For domain age lookup
const ogs = require('open-graph-scraper');

module.exports = { 
    version,
    checkPasswordStrength,
    generatePassword,
    calculateRisk,
    loadData,
    loadConfig
};

//Function to specify build date and version
function version(){
    const versionstring = '0.03';
    const buildDateString  = '02/04/2025';
    const [day, month, year] = buildDateString.split('/'); // Split the string into day, month, and year
    const buildDate = new Date(year, month - 1, day); // Month is 0-indexed, so subtract 1 from the month

    return `Phishing API Version: ${versionstring}\nBuild Date: ${buildDateString}\nAPI age: ${timeAgo(buildDate)}`;
}

//Function to estimate API age
function timeAgo(timestamp) {
    const now = new Date();
    const timeDifference = now - new Date(timestamp); // Difference in milliseconds
    
    const seconds = Math.floor(timeDifference / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const months = Math.floor(days / 30.44); // Average month length
    const years = Math.floor(months / 12);

    if (seconds < 60) {
        return `${seconds} second(s) ago`;
    } else if (minutes < 60) {
        return `${minutes} minute(s) ago`;
    } else if (hours < 24) {
        return `${hours} hour(s) ago`;
    } else if (days < 30) {
        return `${days} day(s) ago`;
    } else if (months < 12) {
        return `${months} month(s) ago`;
    } else {
        return `${years} year(s) ago`;
    }
}

// Function to load JSON data from a file
function loadData(fileName) {
    try {
        return JSON.parse(fs.readFileSync(fileName, 'utf-8'));
    } catch (error) {
        console.error(`Error loading file ${fileName}:`, error.message);
        return []; // Return an empty array to avoid breaking execution
    }
}

// Load configuration settings
function loadConfig() {
    try {
        return JSON.parse(fs.readFileSync('./PhishingAuthorityData/config.json', 'utf-8'));
    } catch (error) {
        console.error("Error loading config.json:", error.message);
        console.error("Default config used");
        return {
            enableAPI: false,
            useWhitelist: false,
            useSuspiciousDomains: false,
            useSuspiciousKeywords: false,
            useBlockedDomains: false,
            useDNSResolve: false,
            useDomainAgeCheck: false,
            useDnsProviderCheck: false,
            useEncodedCharsCheck: false
        }; // Default to all false if config is missing
        
    }
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
const axios = require('axios');

// Function to check SSL certificate details using SSL Labs API
async function checkSSL(domain) {
    try {
        const sslApiUrl = `https://api.ssllabs.com/api/v3/analyze?host=${domain}`;

        // Fetch SSL certificate details from SSL Labs API
        const response = await axios.get(sslApiUrl);

        if (response.status === 200) {
            const sslData = response.data;

            if (sslData.status === 'READY') {
                // SSL certificate details are available
                const grade = sslData.grade || 'N/A';
                const issues = sslData.certChain ? sslData.certChain.map(cert => cert.issuerLabel) : 'No certificate chain';
                const isExpired = sslData.endpoints && sslData.endpoints[0].expireDate < Date.now() / 1000; // Check if certificate expired

                return {
                    grade,
                    issues,
                    isExpired,
                };
            } else if (sslData.status === 'ERROR') {
                // Handle SSL Labs API error
                return { error: 'SSL Labs API encountered an error analyzing the domain.' };
            } else {
                return { error: 'SSL certificate analysis is still in progress.' };
            }
        } else {
            return { error: 'Failed to fetch SSL information from SSL Labs API.' };
        }
    } catch (error) {
        console.error('Error fetching SSL data:', error);
        return { error: 'Error fetching SSL data from the SSL Labs API.' };
    }
}

// Calculate risk based on URL
async function calculateRisk(url) {
    try {
        // Check if the URL starts with "http://" or "https://", if not, prepend "http://"
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            console.log("Prepending http:// to URL because it doesn't start with a protocol.");
            url = 'http://' + url; // Prepend http:// if missing
        }

        // Log the URL being passed in for debugging purposes
        console.log("Checking URL:", url);

        // Try to parse the URL
        const parsed = new URL(url);
        console.log("Parsed URL:", parsed); // Log the parsed URL to check if it's correct

        const config = loadConfig(); // Load config settings
        
        const whitelistedDomains = config.useWhitelist ? loadData('./PhishingAuthorityData/whitelistedDomains.json') : [];
        const suspiciousDomains = config.useSuspiciousDomains ? loadData('./PhishingAuthorityData/suspiciousDomains.json') : [];
        const suspiciousKeywords = config.useSuspiciousKeywords ? loadData('./PhishingAuthorityData/suspiciousKeywords.json') : [];
        const blockedDomains = config.useBlockedDomains ? loadData('./PhishingAuthorityData/blockedDomains.json') : [];
        
        let risk = 0;
        let reasons = [];
        let domain = parsed.hostname.toLowerCase().replace(/^www\./, ''); // Remove www if present
        const fullUrl = (domain + parsed.pathname + parsed.search).toLowerCase();
        
        // Check if the site uses HTTP instead of HTTPS
        if (parsed.protocol === 'http:') {
            risk += 40;
            reasons.push("Uses HTTP instead of HTTPS (less secure).");
        }

        // Check if the domain is whitelisted
        if (config.useWhitelist && !whitelistedDomains.whitelistedDomains.includes(domain)) {
            risk += 20;
            reasons.push("Domain is not in the trusted whitelist.");
        }

        // Check for suspicious keywords in the URL
        if (config.useSuspiciousKeywords) {
            suspiciousKeywords.suspiciousKeywords.forEach(keyword => {
                if (fullUrl.includes(keyword)) {
                    risk += 30;
                    reasons.push(`Contains suspicious keyword: '${keyword}'.`);
                }
            });
        }

        // Check if the domain is part of suspicious domain extensions
        if (config.useSuspiciousDomains) {
            suspiciousDomains.suspiciousDomains.forEach(suspicious => {
                if (domain.endsWith(suspicious)) {
                    risk += 30;
                    reasons.push(`Domain has a suspicious extension: '${suspicious}'.`);
                }
            });
        }

        // Check if the domain is in the blocked list
        if (config.useBlockedDomains && blockedDomains.blockedDomains.includes(domain)) {
            risk += 100;
            reasons.push(`Domain is explicitly BLOCKED (${domain}).`);
        }

        // Check if the domain is in DNS Resolve
        if (config.useDNSResolve) {
            checkDNS(domain).then(isResolved => {
                if (!isResolved) {
                    risk += 30;
                    reasons.push(`Domain ${domain} does not resolve correctly via DNS.`);
                }
            }).catch(err => {
                console.log("Error checking DNS resolution:", err);
            });
        }

        // Check for domain age
        if (config.useDomainAgeCheck) {
            getDomainAge(domain).then(age => {
                if (age && age < 1) { // Less than 1 year old is risky
                    risk += 20;
                    reasons.push(`Domain is less than 1 year old (${age.toFixed(2)} years).`);
                }
            }).catch(err => {
                console.log("Error checking domain age:", err);
                reasons.push(`Unable to check domain age.`);
            });
        }

        // Check DNS provider
        if (config.useDnsProviderCheck) {
            checkDnsProvider(domain).then(isSuspicious => {
                if (isSuspicious) {
                    risk += 30;
                    reasons.push(`Domain uses a suspicious DNS provider.`);
                }
            }).catch(err => {
                console.log("Error checking DNS provider:", err);
                reasons.push(`Unable to check DNS provider.`);
            });
        }

        if (config.useMetaData && !whitelistedDomains.whitelistedDomains.includes(domain)) {
            const { plainText, isObfuscated } = await getMetaData(url);  // Destructuring the returned object from getMetaData
            
            if (typeof plainText === 'string' && plainText.trim().length > 0) {
                const textContent = plainText.toLowerCase();  // Safe to call `.toLowerCase()` on plainText
                
                // Check for suspicious keywords in the page content
                suspiciousKeywords.suspiciousKeywords.forEach(keyword => {
                    if (textContent.includes(keyword)) {
                        risk += 30;
                        reasons.push(`Page contains suspicious keyword: '${keyword}'.`);
                    }
                });
            } else {
                console.log("Failed to fetch metadata or page content is empty.");
                reasons.push("Unable to fetch webpage content for analysis.");
            }
        
            // If the page is obfuscated, add a risk score
            if (isObfuscated) {
                console.log("page is obfuscated.")
                risk += 20;
                reasons.push("Page content appears obfuscated (encoded characters detected).");
            }
        }

        // Check for encoded characters in the URL
        if (config.useEncodedCharsCheck && containsEncodedChars(url)) {
            risk += 20;
            reasons.push("URL contains percent-encoded characters (possible obfuscation).");
        }
        if (config.useWhitelist && whitelistedDomains.whitelistedDomains.includes(domain)) risk = 0; // Return -999 if the domain is whitelisted
                
        // Run SSL check for the domain
        const sslResult = await checkSSL(domain);

        let sslMessage = '';
        let sslRisk = 0;
        
        if (sslResult.error) {
            sslMessage = `Error fetching SSL info: ${sslResult.error}`;
        } else {
            if (sslResult.grade === 'A' || sslResult.grade === 'A+') {
                sslMessage = 'The domain has a strong SSL certificate.';
            } else {
                sslRisk += 30; // Add risk if the certificate grade is not A
                sslMessage = `The domain has an SSL grade of '${sslResult.grade}', which may not be secure.`;
            }

            if (sslResult.isExpired) {
                sslRisk += 50; // Add higher risk if the certificate is expired
                sslMessage += ' The SSL certificate has expired!';
            }
        }
        // Add SSL risk score to the overall risk score
        risk += sslRisk;
        reasons.push(sslMessage);
        // Assign a proper risk message
        let safetyMessage = "";
        if (risk === 0) {
            safetyMessage = "This URL appears to be safe!";
        } else if (risk > 0 && risk <= 20) {
            safetyMessage = "Low risk. Proceed with caution.";
        } else if (risk > 20 && risk <= 50) {
            safetyMessage = "Medium risk. Be cautious when interacting with this URL.";
        } else if (risk > 50 && risk < 100) {
            safetyMessage = "High risk. This URL is highly suspicious, do not interact with it!";
        } else if (risk >= 100) {
            safetyMessage = "Very high risk. This URL is extremely dangerous, avoid interacting with it!";
        } else {
            safetyMessage = "Our service has encountered a problem attempting to provide a safety message, use the risk score to decide if you should proceed. Anything over 30 is reason to be extremely cautious!";
        }
        reasons.push(`Risk Score: ${risk}`);
        return {
            risk,
            safetyMessage,
            reasons,
        };
    } catch (error) {
        // Detailed error handling to explain why the URL can't be analyzed
        let errorMessage = "Unable to analyze the URL due to the following issue:\n";

        // Check if it's a URL parsing error
        if (error instanceof TypeError && error.message.includes("Invalid URL")) {
            errorMessage += "The URL format is invalid. This may be due to missing or incorrect protocol (e.g., 'http://' or 'https://').";
        } else {
            errorMessage += `Error: ${error.message}`;
        }

        console.error("Error details:", errorMessage); // Log detailed error

        return {
            risk: 100,
            safetyMessage: "Invalid URL format. Unable to analyze risk.",
            reasons: [errorMessage], // Provide the detailed error message as the reason
        };
    }
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

// Function to check DNS resolution and mail exchange (MX) records
function checkDNS(domain) {
    return new Promise((resolve, reject) => {
        // Try resolving the domain's A record (IPv4 address)
        dns.resolve(domain, 'A', (err, addresses) => {
            if (err || addresses.length === 0) {
                resolve(false); // If no addresses are returned, consider it unresolved
            } else {
                // Optionally, you can also check MX records for email servers
                dns.resolveMx(domain, (mxErr, mxRecords) => {
                    if (mxErr || mxRecords.length === 0) {
                        resolve(false); // No mail exchange records, possibly suspicious
                    } else {
                        resolve(true); // Domain resolves and has mail servers
                    }
                });
            }
        });
    });
}

function getDomainAge(domain) {
    return new Promise((resolve, reject) => {
        whois.lookup(domain, function(err, data) {
            if (err) {
                reject(err);
            } else {
                // Extract the domain creation date from the WHOIS response
                const matches = data.match(/Creation Date: (.*)/);
                if (matches && matches[1]) {
                    const creationDate = new Date(matches[1]);
                    const age = (new Date() - creationDate) / (1000 * 3600 * 24 * 365); // Age in years
                    resolve(age);
                } else {
                    resolve(null); // Unable to get domain age
                }
            }
        });
    });
}

function checkDnsProvider(domain) {
    return new Promise((resolve, reject) => {
        dns.resolve(domain, (err, addresses) => {
            if (err) {
                resolve(false);
            } else {
                // Add logic to check if addresses belong to a suspicious provider
                const suspiciousIps = ['192.0.2.0', '203.0.113.0']; // Example suspicious IPs
                if (addresses.some(ip => suspiciousIps.includes(ip))) {
                    resolve(true);
                } else {
                    resolve(false);
                }
            }
        });
    });
}

// Helper function to detect encoded characters in the page content
function containsEncodedChars(content) {
    const encodedCharsPattern = /%[0-9A-Fa-f]{2}/g; // Pattern to match percent-encoded characters
    const matches = content.match(encodedCharsPattern);
    
    // If there are encoded characters in the content, consider it obfuscated
    return matches && matches.length > 150000; // Consider more than 10 encoded characters as suspicious
}

async function getMetaData(url) {
    const apiUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;

    try {
        const response = await fetch(apiUrl);

        if (response.ok) {
            const data = await response.json();

            if (data && typeof data.contents === "string") {
                // Remove HTML tags & extract plain text
                const plainText = data.contents.replace(/<[^>]*>/g, " ") // Strip HTML tags
                                               .replace(/\s+/g, " ") // Normalize whitespace
                                               .trim() // Remove leading/trailing whitespace
                                               .toLowerCase(); // Convert to lowercase
                
                console.log("Extracted Text:", plainText);

                // Check for obfuscation (encoded characters, suspicious patterns)
                if (containsEncodedChars(data.contents)) {
                    console.log("Obfuscation detected! Adding risk score.");
                    return { plainText, isObfuscated: true };
                } else {
                    return { plainText, isObfuscated: false };
                }
            } else {
                console.error("No valid text content found.");
                return { plainText: null, isObfuscated: false };
            }
        } else {
            console.error(`Failed to fetch metadata. Status: ${response.status}`);
            return { plainText: null, isObfuscated: false };
        }
    } catch (error) {
        console.error("Error fetching metadata:", error);
        return { plainText: null, isObfuscated: false };
    }
}


