// api/threat-intel/virustotal.js
// Converted from api/virustotal.py

export default async function handler(req, res) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    const { ioc } = req.body;
    
    if (!ioc) {
      return res.status(400).json({ error: 'IOC parameter required' });
    }
  
    const VT_API_KEY = process.env.VT_API_KEY;
    
    if (!VT_API_KEY) {
      return res.status(500).json({ error: "Missing VirusTotal API key." });
    }
  
    const headers = {
      "x-apikey": VT_API_KEY,
      "Accept": "application/json"
    };
  
    try {
      // 1. Search
      const searchUrl = `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(ioc)}`;
      const searchResponse = await fetch(searchUrl, { 
        headers, 
        timeout: 10000 
      });
      
      if (!searchResponse.ok) {
        const errorText = await searchResponse.text();
        return res.status(500).json({ 
          error: `VT Search HTTP ${searchResponse.status}`, 
          details: errorText 
        });
      }
  
      const searchData = await searchResponse.json();
      
      if (!searchData.data || searchData.data.length === 0) {
        return res.status(200).json({ message: "No data found in VirusTotal search." });
      }
  
      const item = searchData.data[0];
      const itemId = item.id;
      const itemType = item.type;
  
      if (!itemId || !itemType) {
        return res.status(200).json({ message: "Unable to determine ID/type from VT search result." });
      }
  
      // 2. Main detail query
      const baseDetailUrl = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}`;
      const detailResponse = await fetch(baseDetailUrl, { 
        headers, 
        timeout: 10000 
      });
      
      if (!detailResponse.ok) {
        const errorText = await detailResponse.text();
        return res.status(500).json({ 
          error: `VT Detail HTTP ${detailResponse.status}`, 
          details: errorText 
        });
      }
  
      const details = await detailResponse.json();
  
      // 3. Enrich with related data (where applicable)
      const relatedData = {};
  
      const fetchRelation = async (relationship) => {
        try {
          const url = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}/relationships/${relationship}`;
          const response = await fetch(url, { 
            headers, 
            timeout: 10000 
          });
          
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
  
      return res.status(200).json({
        details: details,
        related: relatedData
      });
  
    } catch (error) {
      console.error('VirusTotal API error:', error);
      return res.status(500).json({ error: error.message });
    }
  }
  
  // Standalone function for use in main analyze endpoint
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
      // 1. Search
      const searchUrl = `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(ioc)}`;
      const searchResponse = await fetch(searchUrl, { 
        headers, 
        timeout: 10000 
      });
      
      if (!searchResponse.ok) {
        const errorText = await searchResponse.text();
        return { 
          error: `VT Search HTTP ${searchResponse.status}`, 
          details: errorText 
        };
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
  
      // 2. Main detail query
      const baseDetailUrl = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}`;
      const detailResponse = await fetch(baseDetailUrl, { 
        headers, 
        timeout: 10000 
      });
      
      if (!detailResponse.ok) {
        const errorText = await detailResponse.text();
        return { 
          error: `VT Detail HTTP ${detailResponse.status}`, 
          details: errorText 
        };
      }
  
      const details = await detailResponse.json();
  
      // 3. Enrich with related data (where applicable)
      const relatedData = {};
  
      const fetchRelation = async (relationship) => {
        try {
          const url = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}/relationships/${relationship}`;
          const response = await fetch(url, { 
            headers, 
            timeout: 10000 
          });
          
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
  
      return {
        details: details,
        related: relatedData
      };
  
    } catch (error) {
      return { error: error.message };
    }
  }