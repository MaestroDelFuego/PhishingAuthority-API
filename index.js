const axios = require('axios');
const phishingAuth = require('./phishingauthority.api.js');


(async () => {
    try {
            const domain = 'www.u.to/89I2Ig';
            const result = await phishingAuth.calculateRisk(domain);
            console.log(`SSL Check Result for ${domain}:`, result);
        
    } catch (error) {
        console.error('Error:', error);
    }
})();