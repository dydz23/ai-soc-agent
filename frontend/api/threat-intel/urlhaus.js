 // api/threat-intel/urlhaus.js
 export async function lookupURLHaus(ioc) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    if (!ABUSECH_API_KEY) {
      return { error: "Missing Abuse.ch API key for URLHaus." };
    }
  
    const trimmedIOC = ioc.trim();
  
    // Check if it's a search query or hash
    if (trimmedIOC.includes(":") && !trimmedIOC.match(/^[a-fA-F0-9]{64}$/)) {
      return await searchURLHaus(trimmedIOC);
    }
  
    // Hash lookup
    let payload;
    if (trimmedIOC.match(/^[a-fA-F0-9]{32}$/)) {
      payload = { md5_hash: trimmedIOC };
    } else if (trimmedIOC.match(/^[a-fA-F0-9]{64}$/)) {
      payload = { sha256_hash: trimmedIOC };
    } else {
      return { error: "Invalid hash format for URLhaus lookup" };
    }
  
    try {
      const response = await fetch("https://urlhaus-api.abuse.ch/v1/payload/", {
        method: 'POST',
        headers: {
          "User-Agent": "ai-soc-agent/1.0",
          "Auth-Key": ABUSECH_API_KEY
        },
        body: new URLSearchParams(payload),
        timeout: 10000
      });
  
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
  
      const data = await response.json();
      
      if (data.query_status === "ok") {
        return {
          found: true,
          "SHA256": data.sha256_hash,
          "MD5": data.md5_hash,
          "File Size": data.file_size,
          "File Type": data.file_type,
          "First Seen": data.firstseen,
          "Last Seen": data.lastseen,
          "URL Count": (data.urls || []).length,
          "URLs": (data.urls || []).slice(0, 3).map(url => url.url)
        };
      } else if (data.query_status === "no_results") {
        return { message: "No URLhaus results found." };
      } else {
        return {
          status: data.query_status,
          reason: data.reason || "No reason provided."
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async function searchURLHaus(term) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    const payload = {
      query: "search",
      search_term: term
    };
    
    try {
      const response = await fetch("https://urlhaus-api.abuse.ch/v1/", {
        method: 'POST',
        headers: {
          "User-Agent": "ai-soc-agent/1.0",
          "Auth-Key": ABUSECH_API_KEY
        },
        body: new URLSearchParams(payload),
        timeout: 10000
      });
  
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
  
      const data = await response.json();
      
      if (data.query_status === "ok" && data.urls) {
        return {
          found: true,
          results: data.urls.slice(0, 5).map(item => ({
            "URL": item.url,
            "Host": item.host,
            "Threat": item.threat,
            "Tags": item.tags,
            "Date Added": item.date_added,
            "Reporter": item.reporter,
            "URL Status": item.url_status,
          }))
        };
      } else if (data.query_status === "no_results") {
        return { message: "No URLhaus search results found." };
      } else {
        return {
          status: data.query_status,
          reason: data.reason || "No data matched."
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }