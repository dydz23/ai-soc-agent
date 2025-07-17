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

// Inline handler implementations
async function handleAnalyze(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    const { input } = req.body;
    const inputValue = input?.trim();

    if (!inputValue) {
      return res.status(400).json({
        detail: "Must provide input value for analysis."
      });
    }

    // Simplified implementation
    return res.status(200).json({
      input: inputValue,
      normalized_input: inputValue,
      type: "simplified",
      type_description: "Simplified Analysis",
      soc_analysis: {
        llm_analysis: "This is a simplified analysis response.",
        confidence_level: "high",
        risk_assessment: {
          level: "low",
          score: 10
        },
        recommended_actions: ["No action needed"],
        timestamp: new Date().toISOString()
      },
      summary: "This is a simplified analysis response."
    });

  } catch (error) {
    console.error('Analysis error:', error);
    return res.status(500).json({
      detail: `Analysis failed: ${error.message}`,
      error_type: error.constructor.name
    });
  }
}

async function handleHealth(req, res) {
  return res.status(200).json({ status: 'healthy' });
}

async function handleQuickAnalyze(req, res) {
  return res.status(200).json({ message: 'Quick analyze endpoint' });
}

async function handleSources(req, res) {
  return res.status(200).json({
    sources: [
      { name: 'VirusTotal', type: 'multi-engine scanner' },
      { name: 'AbuseIPDB', type: 'IP reputation database' },
      { name: 'Shodan', type: 'Internet device search' },
      { name: 'AlienVault OTX', type: 'Threat intelligence platform' },
      { name: 'ThreatFox', type: 'Malware IOC database' },
      { name: 'URLhaus', type: 'Malware URL database' },
      { name: 'MalwareBazaar', type: 'Malware sample database' },
      { name: 'IPInfo', type: 'IP geolocation service' },
      { name: 'URLScan', type: 'URL analysis service' }
    ]
  });
}