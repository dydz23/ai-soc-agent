  // api/threat-intel/threatfox.js
  export async function lookupThreatFox(ioc) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    if (!ABUSECH_API_KEY) {
      return { error: "Missing Abuse.ch API key." };
    }
  
    const url = "https://threatfox-api.abuse.ch/api/v1/";
    const headers = {
      "User-Agent": "ai-soc-agent/1.0",
      "Content-Type": "application/json",
      "Accept": "application/json",
      "Auth-Key": ABUSECH_API_KEY
    };
  
    const payload = {
      query: ioc.startsWith(("ioc:", "malware:", "tag:", "uuid:", "threat_type:")) 
        ? "search_advanced" 
        : "search_ioc",
      search_term: ioc
    };
  
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeout: 10000
      });
      
      if (response.ok) {
        const data = await response.json();
        
        if (data.query_status === "ok") {
          const results = data.data || [];
          return results.length > 0 ? results : { message: "No ThreatFox results found." };
        } else if (data.query_status === "no_result") {
          return { message: "No ThreatFox results found." };
        } else {
          return {
            status: data.query_status,
            reason: data.reason || "No reason provided."
          };
        }
      } else if (response.status === 401) {
        return { error: "HTTP 401 Unauthorized. Check API key and headers." };
      } else {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
    } catch (error) {
      return { error: error.message };
    }
  }