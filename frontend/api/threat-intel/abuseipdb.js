// api/threat-intel/abuseipdb.js
// Converted from api/abuseipdb.py

export default async function handler(req, res) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    const { ip, originalDomain } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP parameter required' });
    }
  
    const result = await checkIP(ip, originalDomain);
    return res.status(200).json(result);
  }
  
  export async function checkIP(ip, originalDomain = null) {
    const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
    
    if (!ABUSEIPDB_API_KEY) {
      return { error: "Missing AbuseIPDB API key." };
    }
  
    const url = "https://api.abuseipdb.com/api/v2/check";
    const params = new URLSearchParams({
      ipAddress: ip,
      maxAgeInDays: "90"
    });
    
    const headers = {
      "Key": ABUSEIPDB_API_KEY,
      "Accept": "application/json"
    };
  
    try {
      const response = await fetch(`${url}?${params}`, { 
        headers, 
        timeout: 10000 
      });
      
      if (response.ok) {
        const responseData = await response.json();
        const data = responseData.data;
        
        const result = {
          "IP Address": data.ipAddress,
          "Abuse Score": data.abuseConfidenceScore,
          "Country": data.countryCode,
          "ISP": data.isp || "N/A",
          "Domain": data.domain || "N/A",
          "Usage Type": data.usageType || "N/A",
          "Total Reports": data.totalReports,
          "Last Reported": data.lastReportedAt || "N/A"
        };
  
        if (originalDomain) {
          result["⚠️ Resolved Lookup"] = `IP shown was resolved from ${originalDomain}`;
        }
  
        return result;
      } else {
        const errorText = await response.text();
        return { 
          error: `AbuseIPDB HTTP ${response.status}`, 
          details: errorText 
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }