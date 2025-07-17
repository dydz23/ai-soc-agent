// api/threat-intel/shodan.js
// Converted from api/shodan_lookup.py

export default async function handler(req, res) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    const { ip } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP parameter required' });
    }
  
    const result = await lookupShodan(ip);
    return res.status(200).json(result);
  }
  
  export async function lookupShodan(ip) {
    const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
    
    if (!SHODAN_API_KEY) {
      return { error: "Missing Shodan API key." };
    }
  
    try {
      const url = `https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`;
      const response = await fetch(url, { timeout: 10000 });
      
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `Shodan API error: ${response.status} - ${errorText}` };
      }
      
      const host = await response.json();
      
      const result = {
        "ip": host.ip_str,
        "organization": host.org,
        "os": host.os,
        "last_update": host.last_update,
        "open_ports": host.ports,
        "hostnames": host.hostnames,
        "country": host.country_name,
        "isp": host.isp,
        "tags": host.tags,
        "vulns": host.vulns ? Array.from(host.vulns) : [],
      };
      
      return result;
    } catch (error) {
      return { error: error.message };
    }
  }