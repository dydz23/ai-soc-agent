// api/threat-intel.js
// Consolidated threat intelligence functions
import fetch from 'node-fetch';

// VirusTotal Function
export async function checkVirusTotal(ioc) {
    const VT_API_KEY = process.env.VT_API_KEY;
    
    if (!VT_API_KEY) {
      return { error: "Missing VirusTotal API key." };
    }
  
    const headers = {
      "x-apikey": VT_API_KEY,
      "Accept": "application/json"
    };
  
    try {
      const searchUrl = `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(ioc)}`;
      const searchResponse = await fetch(searchUrl, { headers, timeout: 10000 });
      
      if (!searchResponse.ok) {
        const errorText = await searchResponse.text();
        return { error: `VT Search HTTP ${searchResponse.status}`, details: errorText };
      }
  
      const searchData = await searchResponse.json();
      
      if (!searchData.data || searchData.data.length === 0) {
        return { message: "No data found in VirusTotal search." };
      }
  
      const item = searchData.data[0];
      const itemId = item.id;
      const itemType = item.type;
  
      if (!itemId || !itemType) {
        return { message: "Unable to determine ID/type from VT search result." };
      }
  
      const baseDetailUrl = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}`;
      const detailResponse = await fetch(baseDetailUrl, { headers, timeout: 10000 });
      
      if (!detailResponse.ok) {
        const errorText = await detailResponse.text();
        return { error: `VT Detail HTTP ${detailResponse.status}`, details: errorText };
      }
  
      const details = await detailResponse.json();
      const relatedData = {};
  
      const fetchRelation = async (relationship) => {
        try {
          const url = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}/relationships/${relationship}`;
          const response = await fetch(url, { headers, timeout: 10000 });
          if (response.ok) {
            const data = await response.json();
            return data.data || [];
          }
          return [];
        } catch (error) {
          return [];
        }
      };
  
      if (itemType === "domain") {
        relatedData.resolutions = await fetchRelation("resolutions");
        relatedData.communicating_files = await fetchRelation("communicating_files");
        relatedData.downloaded_files = await fetchRelation("downloaded_files");
      } else if (itemType === "ip_address") {
        relatedData.resolutions = await fetchRelation("resolutions");
        relatedData.contacted_domains = await fetchRelation("contacted_domains");
      } else if (itemType === "url") {
        relatedData.downloaded_files = await fetchRelation("downloaded_files");
      } else if (itemType === "file") {
        relatedData.contacted_domains = await fetchRelation("contacted_domains");
        relatedData.contacted_ips = await fetchRelation("contacted_ips");
      }
  
      return { details: details, related: relatedData };
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // AbuseIPDB Function
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
      const response = await fetch(`${url}?${params}`, { headers, timeout: 10000 });
      
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
        return { error: `AbuseIPDB HTTP ${response.status}`, details: errorText };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // Shodan Function
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
      
      return {
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
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // OTX Function
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
        return { error: `OTX HTTP ${response.status}`, details: errorText };
      }
    } catch (error) {
      return { error: `Request failed: ${error.message}` };
    }
  }
  
  // ThreatFox Function
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
  
  // URLScan Function
  export async function lookupURLScan(ioc) {
    const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
    if (!URLSCAN_API_KEY) {
      return { error: "Missing URLScan API key." };
    }
  
    let url = ioc;
    if (!url.startsWith("http")) {
      url = "http://" + url;
    }
  
    const headers = {
      "API-Key": URLSCAN_API_KEY,
      "Content-Type": "application/json",
      "Accept": "application/json"
    };
  
    const payload = { url: url, visibility: "public" };
  
    try {
      const postResponse = await fetch("https://urlscan.io/api/v1/scan/", {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeout: 10000
      });
  
      if (!postResponse.ok) {
        const errorText = await postResponse.text();
        return { error: `URLScan Active HTTP ${postResponse.status}`, details: errorText };
      }
  
      const postData = await postResponse.json();
      const scanId = postData.uuid;
      
      // Wait for result with timeout
      const resultUrl = `https://urlscan.io/api/v1/result/${scanId}/`;
      let result = null;
      
      for (let i = 0; i < 6; i++) { // 30 seconds timeout
        try {
          await new Promise(resolve => setTimeout(resolve, 5000));
          const response = await fetch(resultUrl, { headers, timeout: 10000 });
          if (response.ok) {
            result = await response.json();
            break;
          }
        } catch (error) {
          // Continue trying
        }
      }
  
      if (!result) {
        return { error: "URLScan result not ready after timeout." };
      }
  
      const page = result.page || {};
      const lists = result.lists || {};
      const task = result.task || {};
      const verdicts = result.verdicts?.overall || {};
  
      return {
        method: "active",
        summary: {
          "Scan URL": task.url,
          "Scan Time": task.time,
          "Visibility": task.visibility,
          "Verdict Score": verdicts.score,
          "Verdict Tags": (verdicts.tags || []).join(", "),
          "Status": page.status,
          "MIME Type": page.mimeType,
          "Server": page.server,
        },
        domain_info: {
          "Domain": page.domain,
          "IP": page.ip,
          "ASN": page.asn,
          "ASN Name": page.asnname,
          "Country": page.country,
          "TLS Issuer": page.tlsIssuer,
        },
        http: {
          "Redirects": (lists.redirects || []).map(r => r.response?.url).filter(Boolean),
          "Indicators": lists.verdicts || {},
          "Behaviors": lists.behavior || {},
        },
        screenshot: result.screenshot,
        reportURL: task.reportURL,
        raw: result
      };
  
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // URLHaus Function
  export async function lookupURLHaus(ioc) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    if (!ABUSECH_API_KEY) {
      return { error: "Missing Abuse.ch API key for URLHaus." };
    }
  
    const trimmedIOC = ioc.trim();
  
    if (trimmedIOC.includes(":") && !trimmedIOC.match(/^[a-fA-F0-9]{64}$/)) {
      return await searchURLHaus(trimmedIOC);
    }
  
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
      } else {
        return { message: "No URLhaus results found." };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async function searchURLHaus(term) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    const payload = { query: "search", search_term: term };
    
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
      } else {
        return { message: "No URLhaus search results found." };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // MalwareBazaar Function
  export async function lookupMalwareBazaar(ioc) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    if (!ABUSECH_API_KEY) {
      return { error: "Missing Abuse.ch API key for MalwareBazaar." };
    }
  
    const trimmedIOC = ioc.trim();
  
    if (trimmedIOC.includes(":") && !trimmedIOC.match(/^[a-fA-F0-9]{32,64}$/)) {
      return await advancedSearchMB(trimmedIOC);
    }
  
    const payload = { query: "get_info", hash: trimmedIOC };
  
    try {
      const response = await fetch("https://mb-api.abuse.ch/api/v1/", {
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
      
      if (data.query_status === "ok" && data.data) {
        const entry = data.data[0];
        return {
          found: true,
          "SHA256": entry.sha256_hash,
          "File Name": entry.file_name,
          "File Type": entry.file_type_mime,
          "File Size": entry.file_size,
          "Signature": entry.signature,
          "Tags": entry.tags,
          "Vendor Detections": entry.vendor_intel || {},
          "Delivery Method": entry.delivery_method,
          "First Seen": entry.first_seen,
          "Last Seen": entry.last_seen,
          "Comment": entry.comment,
          "Reporter": entry.reporter,
          "Intelligence": entry.intelligence || {}
        };
      } else {
        return { message: "Hash not found in MalwareBazaar." };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async function advancedSearchMB(term) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    const payload = { query: "search", search_term: term };
    
    try {
      const response = await fetch("https://mb-api.abuse.ch/api/v1/", {
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
      
      if (data.query_status === "ok" && data.data) {
        return {
          found: true,
          results: data.data.slice(0, 5).map(entry => ({
            "SHA256": entry.sha256_hash,
            "File Name": entry.file_name,
            "File Type": entry.file_type_mime,
            "Signature": entry.signature,
            "Tags": entry.tags,
            "First Seen": entry.first_seen,
            "Reporter": entry.reporter,
            "File Size": entry.file_size
          }))
        };
      } else {
        return { message: "No MalwareBazaar search results found." };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // IPInfo Function
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
  
  // Helper function to resolve domain to IP
  export async function resolveDomain(domain) {
    try {
      // Use DNS over HTTPS as a fallback since Node.js dns module might not be available
      const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
        headers: {
          'Accept': 'application/dns-json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.Answer && data.Answer.length > 0) {
          return data.Answer[0].data;
        }
      }
      
      return null;
    } catch (error) {
      console.error('DNS resolution error:', error);
      return null;
    }
  }
  
  // Main handler for threat-intel endpoint
  export default async function handler(req, res) {
    // Support both GET and POST methods
    // For GET requests, use query parameters
    // For POST requests, use body parameters
    let finalSource, finalIoc, finalIocType, finalDomain;
    
    if (req.method === 'GET') {
      const { source, query, type, domain } = req.query || {};
      finalSource = source;
      finalIoc = query;
      finalIocType = type;
      finalDomain = domain;
    } else {
      const { source, ioc, iocType, originalDomain } = req.body || {};
      finalSource = source;
      finalIoc = ioc;
      finalIocType = iocType;
      finalDomain = originalDomain;
    }
    
    if (!finalSource || !finalIoc) {
      return res.status(400).json({ error: 'Source and IOC parameters required' });
    }
  
    let result;
    
    try {
      switch (finalSource) {
        case 'virustotal':
          result = await checkVirusTotal(finalIoc);
          break;
        case 'abuseipdb':
          result = await checkIP(finalIoc, finalDomain);
          break;
        case 'shodan':
          result = await lookupShodan(finalIoc);
          break;
        case 'otx':
          result = await lookupOTX(finalIoc, finalIocType);
          break;
        case 'threatfox':
          result = await lookupThreatFox(finalIoc);
          break;
        case 'urlscan':
          result = await lookupURLScan(finalIoc);
          break;
        case 'urlhaus':
          result = await lookupURLHaus(finalIoc);
          break;
        case 'malwarebazaar':
          result = await lookupMalwareBazaar(finalIoc);
          break;
        case 'ipinfo':
          result = await lookupIPInfo(finalIoc, finalDomain);
          break;
        default:
          return res.status(400).json({ error: 'Unsupported threat intelligence source' });
      }
      
      return res.status(200).json(result);
    } catch (error) {
      console.error(`Error in ${finalSource}:`, error);
      return res.status(500).json({ error: error.message });
    }
  }