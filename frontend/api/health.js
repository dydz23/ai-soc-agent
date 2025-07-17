// api/health.js

export default async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }
  
    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    try {
      // Basic health check with environment validation
      const healthStatus = {
        status: "healthy",
        service: "Unified Threat Analyzer",
        timestamp: new Date().toISOString(),
        version: "2.0",
        environment: "serverless",
        api_keys_configured: {
          claude: !!process.env.CLAUDE_API_KEY,
          virustotal: !!process.env.VT_API_KEY,
          abuseipdb: !!process.env.ABUSEIPDB_API_KEY,
          shodan: !!process.env.SHODAN_API_KEY,
          otx: !!process.env.OTX_API_KEY,
          urlscan: !!process.env.URLSCAN_API_KEY,
          abusech: !!process.env.ABUSECH_API_KEY,
          ipinfo: !!process.env.IPINFO_TOKEN
        }
      };
  
      // Check if critical API keys are missing
      const missingKeys = Object.entries(healthStatus.api_keys_configured)
        .filter(([key, configured]) => !configured)
        .map(([key]) => key);
  
      if (missingKeys.length > 0) {
        healthStatus.status = "degraded";
        healthStatus.warnings = [`Missing API keys: ${missingKeys.join(', ')}`];
      }
  
      return res.status(200).json(healthStatus);
  
    } catch (error) {
      console.error('Health check error:', error);
      return res.status(500).json({
        status: "unhealthy",
        service: "Unified Threat Analyzer",
        timestamp: new Date().toISOString(),
        error: error.message
      });
    }
  }