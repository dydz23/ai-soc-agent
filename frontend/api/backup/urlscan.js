  // api/threat-intel/urlscan.js
  export async function lookupURLScan(ioc) {
    const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
    if (!URLSCAN_API_KEY) {
      return { error: "Missing URLScan API key." };
    }
  
    let url = ioc;
    if (!url.startsWith("http")) {
      url = "http://" + url;
    }
  
    return await activeScan(url);
  }
  
  async function activeScan(url) {
    const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
    const headers = {
      "API-Key": URLSCAN_API_KEY,
      "Content-Type": "application/json",
      "Accept": "application/json"
    };
  
    const payload = {
      url: url,
      visibility: "public"
    };
  
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
      const result = await waitForResult(scanId);
  
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
  
  async function waitForResult(scanId, timeout = 30000, interval = 5000) {
    const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
    const headers = {
      "API-Key": URLSCAN_API_KEY,
      "Content-Type": "application/json",
      "Accept": "application/json"
    };
  
    const resultUrl = `https://urlscan.io/api/v1/result/${scanId}/`;
    const maxAttempts = Math.floor(timeout / interval);
    
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const response = await fetch(resultUrl, { headers, timeout: 10000 });
        if (response.ok) {
          return await response.json();
        }
      } catch (error) {
        // Continue trying
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    return null;
  }