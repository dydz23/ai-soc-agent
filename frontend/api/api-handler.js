// Consolidated API handler for non-threat-intel endpoints
export default async function handler(req, res) {
    const { endpoint } = req.query;

    // Route to the appropriate handler based on the endpoint parameter
    switch (endpoint) {
        case 'analyze':
            return handleAnalyze(req, res);
        case 'health':
            return handleHealth(req, res);
        case 'quick-analyze':
            return handleQuickAnalyze(req, res);
        case 'sources':
            return handleSources(req, res);
        default:
            return res.status(400).json({ error: 'Invalid API endpoint' });
    }
}

// Import the handler logic from each file
async function handleAnalyze(req, res) {
    const module = await import('./lib/analyze.js');
    return module.default(req, res);
}

async function handleHealth(req, res) {
    const module = await import('./lib/health.js');
    return module.default(req, res);
}

async function handleQuickAnalyze(req, res) {
    const module = await import('./lib/quick-ananalyze.js');
    return module.default(req, res);
}

async function handleSources(req, res) {
    const module = await import('./lib/sources.js');
    return module.default(req, res);
}