// api/sources.js

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
      const sourcesInfo = {
        sources: [
          {
            name: "VirusTotal",
            type: "Multi-engine malware scanner",
            supported_iocs: ["ip", "domain", "hash", "url"],
            description: "Comprehensive malware analysis using 70+ antivirus engines",
            api_configured: !!process.env.VT_API_KEY
          },
          {
            name: "AbuseIPDB",
            type: "IP reputation database",
            supported_iocs: ["ip"],
            description: "Community-driven IP abuse reporting and checking",
            api_configured: !!process.env.ABUSEIPDB_API_KEY
          },
          {
            name: "Shodan",
            type: "Internet-connected device search",
            supported_iocs: ["ip"],
            description: "Search engine for Internet-connected devices and services",
            api_configured: !!process.env.SHODAN_API_KEY
          },
          {
            name: "AlienVault OTX",
            type: "Threat intelligence platform",
            supported_iocs: ["ip", "domain", "hash"],
            description: "Open Threat Exchange collaborative threat intelligence",
            api_configured: !!process.env.OTX_API_KEY
          },
          {
            name: "ThreatFox",
            type: "Malware IOC database",
            supported_iocs: ["ip", "domain", "hash", "advanced_queries"],
            description: "Real-time IOC database by abuse.ch",
            api_configured: !!process.env.ABUSECH_API_KEY
          },
          {
            name: "URLhaus",
            type: "Malware URL database",
            supported_iocs: ["hash", "url"],
            description: "Malware URL sharing and analysis by abuse.ch",
            api_configured: !!process.env.ABUSECH_API_KEY
          },
          {
            name: "MalwareBazaar",
            type: "Malware sample database",
            supported_iocs: ["hash"],
            description: "Malware sample sharing platform by abuse.ch",
            api_configured: !!process.env.ABUSECH_API_KEY
          },
          {
            name: "IPInfo",
            type: "IP geolocation service",
            supported_iocs: ["ip"],
            description: "Comprehensive IP address geolocation and ISP information",
            api_configured: !!process.env.IPINFO_TOKEN
          },
          {
            name: "URLScan",
            type: "URL analysis service",
            supported_iocs: ["url", "domain"],
            description: "Website analysis and screenshot service",
            api_configured: !!process.env.URLSCAN_API_KEY
          }
        ],
        analyst_capabilities: [
          "Risk assessment and scoring",
          "Multi-source correlation",
          "TTPs identification",
          "Threat attribution",
          "Actionable recommendations",
          "Confidence assessment",
          "Real-time analysis",
          "Professional reporting"
        ],
        supported_ioc_types: [
          {
            type: "ip",
            description: "IPv4 and IPv6 addresses",
            examples: ["8.8.8.8", "2001:4860:4860::8888"]
          },
          {
            type: "domain",
            description: "Domain names and hostnames",
            examples: ["example.com", "malicious.domain.org"]
          },
          {
            type: "url",
            description: "Complete URLs",
            examples: ["https://example.com/malware", "http://suspicious.site/payload"]
          },
          {
            type: "hash",
            description: "File hashes (MD5, SHA1, SHA256, etc.)",
            examples: ["d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709"]
          },
          {
            type: "threatfox_query",
            description: "Advanced ThreatFox search queries",
            examples: ["malware:emotet", "tag:apt29", "ioc:example.com"]
          }
        ],
        architecture: {
          frontend: "React + Vite + TailwindCSS",
          backend: "Vercel Serverless Functions",
          ai_engine: "Claude Sonnet",
          deployment: "Vercel Edge Network"
        },
        statistics: {
          total_sources: 9,
          configured_sources: 0, // Will be calculated
          supported_ioc_types: 5,
          serverless_functions: 5
        },
        timestamp: new Date().toISOString()
      };
  
      // Calculate configured sources
      sourcesInfo.statistics.configured_sources = sourcesInfo.sources.filter(
        source => source.api_configured
      ).length;
  
      // Add health status
      const configuredCount = sourcesInfo.statistics.configured_sources;
      const totalCount = sourcesInfo.statistics.total_sources;
      
      if (configuredCount === totalCount) {
        sourcesInfo.health_status = "optimal";
      } else if (configuredCount >= totalCount * 0.7) {
        sourcesInfo.health_status = "good";
      } else if (configuredCount >= totalCount * 0.4) {
        sourcesInfo.health_status = "limited";
      } else {
        sourcesInfo.health_status = "degraded";
      }
  
      return res.status(200).json(sourcesInfo);
  
    } catch (error) {
      console.error('Sources info error:', error);
      return res.status(500).json({
        error: "Failed to retrieve sources information",
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }