 // api/threat-intel/ipinfo.js
 export async function lookupIPInfo(ip, originalDomain = null) {
    const IPINFO_API_KEY = process.env.IPINFO_TOKEN;
    if (!IPINFO_API_KEY) {
      return { error: "Missing IPinfo API key." };
    }
  
    const url = `https://ipinfo.io/${ip}/json`;
    const headers = {
      "Authorization": `Bearer ${IPINFO_API_KEY}`
    };
  
    try {
      const response = await fetch(url, { headers, timeout: 10000 });
      
      if (response.ok) {
        const data = await response.json();
        const result = {
          "IP": data.ip,
          "Hostname": data.hostname,
          "City": data.city,
          "Region": data.region,
          "Country": data.country,
          "Organization": data.org,
          "ASN": data.asn?.asn || "N/A"
        };
  
        if (originalDomain) {
          result["⚠️ Resolved Lookup"] = `IP shown was resolved from ${originalDomain}`;
        }
  
        return result;
      } else {
        const errorText = await response.text();
        return { error: `IPinfo HTTP ${response.status}`, details: errorText };
      }
    } catch (error) {
      return { error: error.message };
    }
  }