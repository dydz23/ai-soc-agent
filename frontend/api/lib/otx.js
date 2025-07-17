// api/threat-intel/otx.js
export default async function handler(req, res) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    const { ioc, iocType } = req.body;
    const result = await lookupOTX(ioc, iocType);
    return res.status(200).json(result);
  }
  
  function sanitizeIOC(ioc, iocType) {
    if (iocType === "url") {
      try {
        const url = new URL(ioc.startsWith('http') ? ioc : `http://${ioc}`);
        return url.hostname || ioc;
      } catch {
        return ioc;
      }
    }
    return ioc;
  }
  
  export async function lookupOTX(ioc, iocType) {
    const OTX_API_KEY = process.env.OTX_API_KEY;
    if (!OTX_API_KEY) {
      return { error: "Missing OTX API key." };
    }
  
    const sanitizedIOC = sanitizeIOC(ioc, iocType);
    const baseUrl = "https://otx.alienvault.com/api/v1/indicators";
  
    let url;
    if (iocType === "ip") {
      url = `${baseUrl}/IPv4/${sanitizedIOC}/general`;
    } else if (iocType === "domain" || iocType === "url") {
      url = `${baseUrl}/domain/${sanitizedIOC}/general`;
    } else if (iocType === "hash") {
      url = `${baseUrl}/file/${sanitizedIOC}/general`;
    } else {
      return { error: `Unsupported IOC type for OTX: ${iocType}` };
    }
  
    const headers = {
      "X-OTX-API-KEY": OTX_API_KEY,
      "User-Agent": "ai-soc-agent"
    };
  
    try {
      const response = await fetch(url, { headers, timeout: 10000 });
      if (response.ok) {
        return await response.json();
      } else {
        const errorText = await response.text();
        return {
          error: `OTX HTTP ${response.status}`,
          details: errorText
        };
      }
    } catch (error) {
      return { error: `Request failed: ${error.message}` };
    }
  }
  