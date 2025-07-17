// Consolidated threat intelligence API handler
export default async function handler(req, res) {
    const { source, query } = req.query;

    // Route to the appropriate handler based on the source parameter
    switch (source) {
        case 'abuseipdb':
            return handleAbuseIPDB(req, res);
        case 'ipinfo':
            return handleIPInfo(req, res);
        case 'malwarebazaar':
            return handleMalwareBazaar(req, res);
        case 'otx':
            return handleOTX(req, res);
        case 'shodan':
            return handleShodan(req, res);
        case 'threatfox':
            return handleThreatFox(req, res);
        case 'urlhaus':
            return handleURLhaus(req, res);
        case 'urlscan':
            return handleURLscan(req, res);
        case 'virustotal':
            return handleVirusTotal(req, res);
        default:
            return res.status(400).json({ error: 'Invalid threat intelligence source' });
    }
}

// Import the handler logic from each file
async function handleAbuseIPDB(req, res) {
    const module = await import('./lib/abuseipdb.js');
    return module.default(req, res);
}

async function handleIPInfo(req, res) {
    const module = await import('./lib/ipinfo.js');
    return module.default(req, res);
}

async function handleMalwareBazaar(req, res) {
    const module = await import('./lib/malwarebazaar.js');
    return module.default(req, res);
}

async function handleOTX(req, res) {
    const module = await import('./lib/otx.js');
    return module.default(req, res);
}

async function handleShodan(req, res) {
    const module = await import('./lib/shodan.js');
    return module.default(req, res);
}

async function handleThreatFox(req, res) {
    const module = await import('./lib/threatfox.js');
    return module.default(req, res);
}

async function handleURLhaus(req, res) {
    const module = await import('./lib/urlhaus.js');
    return module.default(req, res);
}

async function handleURLscan(req, res) {
    const module = await import('./lib/urlscan.js');
    return module.default(req, res);
}

async function handleVirusTotal(req, res) {
    const module = await import('./lib/virustotal.js');
    return module.default(req, res);
}