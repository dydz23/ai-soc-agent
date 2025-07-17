// Consolidated threat intelligence API handler
import fetch from 'node-fetch';
import dns from 'dns';
import { promisify } from 'util';

// Promisify DNS lookup
const dnsLookup = promisify(dns.lookup);

export default async function handler(req, res) {
  const { source, query, type, domain } = req.query;
  
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

// Handler implementations
async function handleAbuseIPDB(req, res) {
  const { query, domain } = req.query;
  try {
    const result = await checkIP(query, domain);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleIPInfo(req, res) {
  const { query, domain } = req.query;
  try {
    const result = await lookupIPInfo(query, domain);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleMalwareBazaar(req, res) {
  const { query } = req.query;
  try {
    const result = await lookupMalwareBazaar(query);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleOTX(req, res) {
  const { query, type } = req.query;
  try {
    const result = await lookupOTX(query, type);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleShodan(req, res) {
  const { query } = req.query;
  try {
    const result = await lookupShodan(query);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleThreatFox(req, res) {
  const { query } = req.query;
  try {
    const result = await lookupThreatFox(query);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleURLhaus(req, res) {
  const { query } = req.query;
  try {
    const result = await lookupURLHaus(query);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleURLscan(req, res) {
  const { query } = req.query;
  try {
    const result = await lookupURLScan(query);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

async function handleVirusTotal(req, res) {
  const { query } = req.query;
  try {
    const result = await checkVirusTotal(query);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

// Actual threat intelligence implementations
async function checkIP(ip, domain = null) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return { error: "AbuseIPDB API key not configured" };
  }

  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=true`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      ...data,
      domain: domain || null
    };
  } catch (error) {
    console.error('AbuseIPDB lookup error:', error);
    return { error: error.message };
  }
}

async function lookupIPInfo(ip, domain = null) {
  const apiKey = process.env.IPINFO_API_KEY;
  if (!apiKey) {
    return { error: "IPInfo API key not configured" };
  }

  try {
    const response = await fetch(`https://ipinfo.io/${ip}?token=${apiKey}`);
    
    if (!response.ok) {
      throw new Error(`IPInfo API error: ${response.statusText}`);
    }
    
    const data = await response.json();
    return {
      ...data,
      domain: domain || null
    };
  } catch (error) {
    console.error('IPInfo lookup error:', error);
    return { error: error.message };
  }
}

async function lookupMalwareBazaar(hash) {
  try {
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `query=get_info&hash=${hash}`
    });

    if (!response.ok) {
      throw new Error(`MalwareBazaar API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('MalwareBazaar lookup error:', error);
    return { error: error.message };
  }
}

async function lookupOTX(query, type) {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) {
    return { error: "OTX API key not configured" };
  }

  let section;
  switch (type) {
    case 'ip':
      section = 'ip';
      break;
    case 'domain':
      section = 'domain';
      break;
    case 'hash':
      section = 'file';
      break;
    default:
      section = 'general';
  }

  try {
    const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/${section}/${query}/general`, {
      headers: {
        'X-OTX-API-KEY': apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`OTX API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('OTX lookup error:', error);
    return { error: error.message };
  }
}

async function lookupShodan(ip) {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) {
    return { error: "Shodan API key not configured" };
  }

  try {
    const response = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
    
    if (!response.ok) {
      throw new Error(`Shodan API error: ${response.statusText}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Shodan lookup error:', error);
    return { error: error.message };
  }
}

async function lookupThreatFox(query) {
  try {
    let requestBody;
    
    // Check if the query is a ThreatFox advanced query
    if (query.match(/^(ioc:|tag:|malware:|uuid:|threat_type:)/)) {
      const [prefix, value] = query.split(':');
      requestBody = {
        "query": "search_ioc",
        [prefix]: value
      };
    } else {
      requestBody = {
        "query": "search_ioc",
        "search_term": query
      };
    }

    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      throw new Error(`ThreatFox API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('ThreatFox lookup error:', error);
    return { error: error.message };
  }
}

async function lookupURLHaus(query) {
  try {
    let requestBody;
    
    if (query.match(/^https?:\/\//)) {
      // URL lookup
      requestBody = {
        "url": query
      };
    } else if (query.match(/^[a-fA-F0-9]{32,}$/)) {
      // Hash lookup
      requestBody = {
        "hash": query
      };
    } else {
      // Host lookup
      requestBody = {
        "host": query
      };
    }

    const response = await fetch('https://urlhaus-api.abuse.ch/v1/payload/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      throw new Error(`URLhaus API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('URLhaus lookup error:', error);
    return { error: error.message };
  }
}

async function lookupURLScan(url) {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) {
    return { error: "URLScan API key not configured" };
  }

  try {
    // Submit URL for scanning
    const submitResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': apiKey
      },
      body: JSON.stringify({
        url: url,
        visibility: 'public'
      })
    });

    if (!submitResponse.ok) {
      throw new Error(`URLScan submission error: ${submitResponse.statusText}`);
    }

    const submitData = await submitResponse.json();
    const scanId = submitData.uuid;
    const resultUrl = submitData.api;

    // Wait for scan to complete (simplified)
    await new Promise(resolve => setTimeout(resolve, 10000));

    // Get scan results
    const resultResponse = await fetch(resultUrl);
    if (!resultResponse.ok) {
      throw new Error(`URLScan result error: ${resultResponse.statusText}`);
    }

    const resultData = await resultResponse.json();
    return {
      method: "active",
      summary: resultData.verdicts || {},
      domain_info: resultData.page || {},
      http: resultData.data?.requests?.[0] || {},
      screenshot: resultData.task?.screenshotURL,
      reportURL: submitData.result
    };
  } catch (error) {
    console.error('URLScan lookup error:', error);
    return { error: error.message };
  }
}

async function checkVirusTotal(query) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { error: "VirusTotal API key not configured" };
  }

  try {
    let endpoint;
    
    // Determine the type of query
    if (query.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
      // IP address
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${query}`;
    } else if (query.match(/^[a-fA-F0-9]{32,}$/)) {
      // File hash
      endpoint = `https://www.virustotal.com/api/v3/files/${query}`;
    } else if (query.match(/^https?:\/\//)) {
      // URL
      // Need to encode the URL
      const encodedUrl = encodeURIComponent(query);
      endpoint = `https://www.virustotal.com/api/v3/urls/${encodedUrl}`;
    } else {
      // Domain
      endpoint = `https://www.virustotal.com/api/v3/domains/${query}`;
    }

    const response = await fetch(endpoint, {
      headers: {
        'x-apikey': apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('VirusTotal lookup error:', error);
    return { error: error.message };
  }
}

// Helper function to resolve domain to IP
export async function resolveDomain(domain) {
  try {
    const result = await dnsLookup(domain);
    return result.address;
  } catch (error) {
    console.error(`Failed to resolve domain ${domain}:`, error);
    return null;
  }
}