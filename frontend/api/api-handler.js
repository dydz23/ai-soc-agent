// Consolidated API handler for non-threat-intel endpoints
import fetch from 'node-fetch';
import dns from 'dns';
import { promisify } from 'util';
import { resolveDomain } from './threat-intel';

// Promisify DNS lookup
const dnsLookup = promisify(dns.lookup);

export default async function handler(req, res) {
  const { endpoint } = req.query;
  
  // Route to the appropriate handler based on the endpoint parameter
  switch (endpoint) {
    case 'analyze':
      return handleAnalyze(req, res);
    case 'health':
      return handleHealth(req, res);
    case 'quick-analyze':
      return handleQuickAnalyze(req, res);
    case 'sources':
      return handleSources(req, res);
    default:
      return res.status(400).json({ error: 'Invalid API endpoint' });
  }
}

// Helper functions for IOC detection
function detectInputType(input) {
  if (!input || !input.trim()) return 'unknown';
  
  const value = input.trim();
  
  // ThreatFox advanced queries
  if (value.match(/^(ioc:|tag:|malware:|uuid:|threat_type:)/)) {
    return 'threatfox_query';
  }
  
  // Email addresses
  if (value.match(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
    return 'email';
  }
  
  // URLs
  if (value.match(/^(https?|ftp|ftps|sftp|file):\/\/[\w\.-]+/)) {
    return 'url';
  }
  
  // URL without protocol
  if (value.match(/^[\w\.-]+\/[\w\.-\/]/) && !value.match(/^[a-fA-F0-9]{32,}$/)) {
    return 'url';
  }
  
  // IPv4 addresses
  if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
    const parts = value.split('.');
    if (parts.every(part => parseInt(part) <= 255)) {
      return 'ipv4';
    }
  }
  
  // IPv6 addresses
  if (value.match(/^[a-fA-F0-9:]+$/) && value.includes(':') && value.length > 15) {
    return 'ipv6';
  }
  
  // CIDR notation
  if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)) {
    return 'cidr_ipv4';
  }
  
  if (value.match(/^[a-fA-F0-9:]+\/\d{1,3}$/)) {
    return 'cidr_ipv6';
  }
  
  // Hash types
  if (value.match(/^[a-fA-F0-9]{32}$/)) {
    return 'md5';
  }
  if (value.match(/^[a-fA-F0-9]{40}$/)) {
    return 'sha1';
  }
  if (value.match(/^[a-fA-F0-9]{56}$/)) {
    return 'sha224';
  }
  if (value.match(/^[a-fA-F0-9]{64}$/)) {
    return 'sha256';
  }
  if (value.match(/^[a-fA-F0-9]{96}$/)) {
    return 'sha384';
  }
  if (value.match(/^[a-fA-F0-9]{128}$/)) {
    return 'sha512';
  }
  if (value.match(/^[a-fA-F0-9]{70}$/)) {
    return 'tlsh';
  }
  if (value.match(/^[a-zA-Z0-9+/]{27}=$/)) {
    return 'ssdeep';
  }
  
  // Domains
  if (value.match(/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/)) {
    return 'domain';
  }
  
  return 'unknown';
}

function normalizeIoc(input, type) {
  const value = input.trim();
  
  switch (type) {
    case 'ipv4':
    case 'ipv6':
      return [value, 'ip'];
    
    case 'md5':
    case 'sha1':
    case 'sha224':
    case 'sha256':
    case 'sha384':
    case 'sha512':
    case 'tlsh':
    case 'ssdeep':
      return [value, 'hash'];
    
    case 'url':
      // Add protocol if missing
      if (!value.match(/^[a-zA-Z]+:\/\//)) {
        return [`http://${value}`, 'url'];
      }
      return [value, 'url'];
    
    case 'domain':
      return [value, 'domain'];
    
    case 'threatfox_query':
      return [value, 'threatfox_query'];
    
    default:
      return [value, type];
  }
}

function validateIoc(input, type) {
  if (!input || !input.trim()) {
    return [false, "Input cannot be empty"];
  }
  
  if (type === 'unknown') {
    return [false, "Unknown or unsupported IOC type"];
  }
  
  // Add more validation as needed
  
  return [true, ""];
}

function getIocDescription(type) {
  const descriptions = {
    'ip': 'IP Address',
    'ipv4': 'IPv4 Address',
    'ipv6': 'IPv6 Address',
    'domain': 'Domain Name',
    'url': 'URL/Web Address',
    'hash': 'File Hash',
    'md5': 'MD5 Hash',
    'sha1': 'SHA1 Hash',
    'sha224': 'SHA224 Hash',
    'sha256': 'SHA256 Hash',
    'sha384': 'SHA384 Hash',
    'sha512': 'SHA512 Hash',
    'tlsh': 'TLSH Hash',
    'ssdeep': 'SSDeep Hash',
    'threatfox_query': 'ThreatFox Query',
    'email': 'Email Address',
    'cidr_ipv4': 'IPv4 CIDR Block',
    'cidr_ipv6': 'IPv6 CIDR Block',
    'unknown': 'Unknown Type'
  };
  
  return descriptions[type] || 'Unknown Type';
}

function extractDomainFromUrl(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (e) {
    // If URL parsing fails, try a simple regex
    const match = url.match(/^(?:https?:\/\/)?([^\/]+)/i);
    return match ? match[1] : url;
  }
}

// Helper functions for threat intelligence
async function fetchThreatIntel(source, query, additionalParams = {}) {
  // Build the query string
  const params = new URLSearchParams();
  params.append('source', source);
  params.append('query', query);
  
  // Add any additional parameters
  Object.entries(additionalParams).forEach(([key, value]) => {
    if (value !== null && value !== undefined) {
      params.append(key, value);
    }
  });
  
  // Use relative URL which works in both development and production
  const response = await fetch(`/api/threat-intel?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`${source} API error: ${response.statusText}`);
  }
  return await response.json();
}

async function checkVirusTotal(query) {
  return await fetchThreatIntel('virustotal', query);
}

async function checkIP(ip, domain = null) {
  return await fetchThreatIntel('abuseipdb', ip, { domain });
}

async function lookupShodan(query) {
  return await fetchThreatIntel('shodan', query);
}

async function lookupOTX(query, type) {
  return await fetchThreatIntel('otx', query, { type });
}

async function lookupThreatFox(query) {
  return await fetchThreatIntel('threatfox', query);
}

async function lookupURLScan(query) {
  return await fetchThreatIntel('urlscan', query);
}

async function lookupURLHaus(query) {
  return await fetchThreatIntel('urlhaus', query);
}

async function lookupMalwareBazaar(query) {
  return await fetchThreatIntel('malwarebazaar', query);
}

async function lookupIPInfo(query, domain = null) {
  return await fetchThreatIntel('ipinfo', query, { domain });
}

// Formatter functions
function formatVirusTotal(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    const attributes = data.data?.attributes || {};
    const stats = attributes.last_analysis_stats || {};
    const results = attributes.last_analysis_results || {};
    
    return {
      detection_rate: `${stats.malicious || 0}/${Object.keys(results).length || 0}`,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      results: results,
      attributes: attributes
    };
  } catch (error) {
    return { error: "Failed to format VirusTotal data" };
  }
}

function formatAbuseIPDB(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    const report = data.data || {};
    
    return {
      ip: report.ipAddress,
      domain: data.domain,
      is_public: report.isPublic,
      abuse_score: report.abuseConfidenceScore,
      country_code: report.countryCode,
      country_name: report.countryName,
      isp: report.isp,
      domain: report.domain,
      total_reports: report.totalReports,
      last_reported_at: report.lastReportedAt,
      reports: report.reports || []
    };
  } catch (error) {
    return { error: "Failed to format AbuseIPDB data" };
  }
}

function formatShodan(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    return {
      ip: data.ip_str,
      ports: data.ports || [],
      hostnames: data.hostnames || [],
      country_code: data.country_code,
      country_name: data.country_name,
      city: data.city,
      org: data.org,
      isp: data.isp,
      asn: data.asn,
      last_update: data.last_update,
      vulns: data.vulns || [],
      tags: data.tags || [],
      services: data.data || []
    };
  } catch (error) {
    return { error: "Failed to format Shodan data" };
  }
}

function formatOTX(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    return {
      pulse_count: data.pulse_info?.count || 0,
      pulses: data.pulse_info?.pulses || [],
      reputation: data.reputation,
      sections: data.sections || [],
      malware_families: data.malware_families || [],
      url_list: data.url_list || []
    };
  } catch (error) {
    return { error: "Failed to format OTX data" };
  }
}

function formatThreatFox(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    return {
      query_status: data.query_status,
      ioc_count: data.data?.length || 0,
      iocs: data.data || []
    };
  } catch (error) {
    return { error: "Failed to format ThreatFox data" };
  }
}

function formatURLHaus(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    return {
      query_status: data.query_status,
      payload: data.payload || {},
      urls: data.urls || []
    };
  } catch (error) {
    return { error: "Failed to format URLhaus data" };
  }
}

function formatMalwareBazaar(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    return {
      query_status: data.query_status,
      sample_count: data.data?.length || 0,
      samples: data.data || []
    };
  } catch (error) {
    return { error: "Failed to format MalwareBazaar data" };
  }
}

function formatIPInfo(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    return {
      ip: data.ip,
      hostname: data.hostname,
      city: data.city,
      region: data.region,
      country: data.country,
      loc: data.loc,
      org: data.org,
      postal: data.postal,
      timezone: data.timezone,
      asn: data.asn,
      company: data.company,
      privacy: data.privacy,
      abuse: data.abuse,
      domain: data.domain
    };
  } catch (error) {
    return { error: "Failed to format IPInfo data" };
  }
}

function formatURLScan(data) {
  if (data.error) {
    return { error: data.error };
  }
  
  try {
    return {
      method: data.method || "passive",
      summary: data.summary || {},
      domain_info: data.domain_info || {},
      http: data.http || {},
      screenshot: data.screenshot,
      reportURL: data.reportURL
    };
  } catch (error) {
    return { error: "Failed to format URLScan data" };
  }
}

// Mock SOC Analyst LLM class
class SOCAnalystLLM {
  async generateSOCAnalysis(data) {
    // In a real implementation, this would call an LLM API
    return {
      llm_analysis: "This is a simplified analysis. In production, this would be generated by an LLM.",
      confidence_level: "medium",
      risk_assessment: {
        level: "medium",
        score: 50
      },
      recommended_actions: [
        "Monitor for suspicious activity",
        "Review logs for related indicators"
      ],
      timestamp: new Date().toISOString()
    };
  }
}

// Handler implementations
async function handleAnalyze(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    const { input } = req.body;
    const inputValue = input?.trim();

    if (!inputValue) {
      return res.status(400).json({
        detail: "Must provide input value for analysis."
      });
    }

    // Detect IOC type
    const detectedType = detectInputType(inputValue);
    
    // Validate IOC
    const [isValid, errorMessage] = validateIoc(inputValue, detectedType);
    if (!isValid) {
      return res.status(400).json({
        detail: errorMessage,
        detected_type: detectedType,
        type_description: getIocDescription(detectedType)
      });
    }
    
    // Normalize IOC for API processing
    const [normalizedValue, finalType] = normalizeIoc(inputValue, detectedType);

    // Handle special case: ThreatFox query
    if (finalType === "threatfox_query") {
      const tfRaw = await lookupThreatFox(normalizedValue);
      const formattedTf = formatThreatFox(tfRaw);
      
      const structuredData = {
        input: inputValue,
        normalized_input: normalizedValue,
        type: finalType,
        type_description: getIocDescription(finalType),
        threatfox: formattedTf,
        virustotal: {},
        abuseipdb: {},
        shodan: {},
        otx: {},
        urlhaus: {},
        malwarebazaar: {},
        ipinfo: {},
        urlscan: {}
      };
      
      const socAnalyst = new SOCAnalystLLM();
      const socAnalysis = await socAnalyst.generateSOCAnalysis(structuredData);
      
      return res.status(200).json({
        input: inputValue,
        normalized_input: normalizedValue,
        type: finalType,
        type_description: getIocDescription(finalType),
        threatfox: formattedTf,
        soc_analysis: socAnalysis,
        summary: socAnalysis.llm_analysis
      });
    }

    // Handle unsupported IOC types
    const unsupportedTypes = [
      "email", "cidr_ipv4", "cidr_ipv6", "registry_key", "file_path_windows", 
      "file_path_unix", "mutex", "user_agent", "bitcoin_address", "cve", 
      "asn", "yara_rule", "mac_address", "process_name", "port"
    ];
    
    if (unsupportedTypes.includes(finalType)) {
      return res.status(400).json({
        detail: `IOC type '${getIocDescription(finalType)}' is not yet supported for threat intelligence analysis.`,
        detected_type: finalType,
        type_description: getIocDescription(finalType),
        supported_types: ["ip", "domain", "url", "hash", "threatfox_query"]
      });
    }

    // Convert URL to domain for analysis
    let processedValue = normalizedValue;
    let processedType = finalType;
    
    if (finalType === "url") {
      processedValue = extractDomainFromUrl(normalizedValue);
      processedType = "domain";
    }

    // Initialize results structure
    const results = {
      input: inputValue,
      normalized_input: normalizedValue,
      type: processedType,
      type_description: getIocDescription(processedType),
      virustotal: {},
      abuseipdb: {},
      shodan: {},
      otx: {},
      threatfox: {},
      urlhaus: {},
      malwarebazaar: {},
      ipinfo: {},
      urlscan: {},
    };

    // ---- URLScan Active Scan ----
    if (finalType === "url" || processedType === "domain") {
      try {
        const urlscanRaw = await lookupURLScan(finalType === "url" ? normalizedValue : processedValue);
        if (urlscanRaw?.method === "active") {
          results.urlscan = {
            method: "active",
            summary: urlscanRaw.summary || {},
            domain_info: urlscanRaw.domain_info || {},
            http: urlscanRaw.http || {},
            screenshot: urlscanRaw.screenshot,
            reportURL: urlscanRaw.reportURL
          };
        } else {
          results.urlscan = { message: "URLScan active scan failed." };
        }
      } catch (error) {
        results.urlscan = { error: error.message };
      }
    }

    // ---- Main Threat Intelligence Lookups ----
    let resolvedIp = null;
    
    if (processedType === "domain") {
      resolvedIp = await resolveDomain(processedValue);
      if (!resolvedIp) {
        return res.status(400).json({
          detail: `Failed to resolve domain: ${processedValue}`
        });
      }
      
      // Execute all relevant lookups for domain
      const [abuseResult, ipinfoResult, shodanResult, otxResult, threatfoxResult, vtResult] = await Promise.allSettled([
        checkIP(resolvedIp, processedValue),
        lookupIPInfo(resolvedIp, processedValue),
        lookupShodan(resolvedIp),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        checkVirusTotal(processedValue)
      ]);

      results.abuseipdb = formatAbuseIPDB(abuseResult.status === 'fulfilled' ? abuseResult.value : { error: abuseResult.reason?.message });
      results.ipinfo = formatIPInfo(ipinfoResult.status === 'fulfilled' ? ipinfoResult.value : { error: ipinfoResult.reason?.message });
      results.shodan = formatShodan(shodanResult.status === 'fulfilled' ? shodanResult.value : { error: shodanResult.reason?.message });
      results.otx = formatOTX(otxResult.status === 'fulfilled' ? otxResult.value : { error: otxResult.reason?.message });
      results.threatfox = formatThreatFox(threatfoxResult.status === 'fulfilled' ? threatfoxResult.value : { error: threatfoxResult.reason?.message });
      results.virustotal = formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message });

    } else if (processedType === "ip") {
      // Execute all relevant lookups for IP
      const [abuseResult, shodanResult, ipinfoResult, otxResult, threatfoxResult, vtResult] = await Promise.allSettled([
        checkIP(processedValue),
        lookupShodan(processedValue),
        lookupIPInfo(processedValue),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        checkVirusTotal(processedValue)
      ]);

      results.abuseipdb = formatAbuseIPDB(abuseResult.status === 'fulfilled' ? abuseResult.value : { error: abuseResult.reason?.message });
      results.shodan = formatShodan(shodanResult.status === 'fulfilled' ? shodanResult.value : { error: shodanResult.reason?.message });
      results.ipinfo = formatIPInfo(ipinfoResult.status === 'fulfilled' ? ipinfoResult.value : { error: ipinfoResult.reason?.message });
      results.otx = formatOTX(otxResult.status === 'fulfilled' ? otxResult.value : { error: otxResult.reason?.message });
      results.threatfox = formatThreatFox(threatfoxResult.status === 'fulfilled' ? threatfoxResult.value : { error: threatfoxResult.reason?.message });
      results.virustotal = formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message });

    } else if (processedType === "hash") {
      // Execute all relevant lookups for hash
      const [vtResult, otxResult, threatfoxResult, urlhausResult, mbResult] = await Promise.allSettled([
        checkVirusTotal(processedValue),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        lookupURLHaus(processedValue),
        lookupMalwareBazaar(processedValue)
      ]);

      results.virustotal = formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message });
      results.otx = formatOTX(otxResult.status === 'fulfilled' ? otxResult.value : { error: otxResult.reason?.message });
      results.threatfox = formatThreatFox(threatfoxResult.status === 'fulfilled' ? threatfoxResult.value : { error: threatfoxResult.reason?.message });
      results.urlhaus = formatURLHaus(urlhausResult.status === 'fulfilled' ? urlhausResult.value : { error: urlhausResult.reason?.message });
      results.malwarebazaar = formatMalwareBazaar(mbResult.status === 'fulfilled' ? mbResult.value : { error: mbResult.reason?.message });

    } else {
      return res.status(400).json({
        detail: `Unsupported IOC type for analysis: ${processedType}`
      });
    }

    // ---- Enhanced SOC Analysis ----
    const socAnalyst = new SOCAnalystLLM();
    const socAnalysis = await socAnalyst.generateSOCAnalysis(results);
    
    // Add SOC analysis to results
    results.soc_analysis = socAnalysis;
    
    // Backwards compatibility - keep the summary field
    results.summary = socAnalysis.llm_analysis;
    
    // Add metadata for better tracking
    results.metadata = {
      analyst_version: "2.0",
      confidence_level: socAnalysis.confidence_level,
      risk_level: socAnalysis.risk_assessment.level,
      risk_score: socAnalysis.risk_assessment.score,
      recommended_actions: socAnalysis.recommended_actions,
      analysis_timestamp: socAnalysis.timestamp
    };

    return res.status(200).json(results);

  } catch (error) {
    console.error('Analysis error:', error);
    return res.status(500).json({
      detail: `Analysis failed: ${error.message}`,
      error_type: error.constructor.name
    });
  }
}

async function handleHealth(req, res) {
  return res.status(200).json({ 
    status: 'healthy',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
}

async function handleQuickAnalyze(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    const { input } = req.body;
    const inputValue = input?.trim();

    if (!inputValue) {
      return res.status(400).json({
        detail: "Must provide input value for analysis."
      });
    }

    // Detect IOC type
    const detectedType = detectInputType(inputValue);
    
    // Validate IOC
    const [isValid, errorMessage] = validateIoc(inputValue, detectedType);
    if (!isValid) {
      return res.status(400).json({
        detail: errorMessage,
        detected_type: detectedType,
        type_description: getIocDescription(detectedType)
      });
    }
    
    // Normalize IOC for API processing
    const [normalizedValue, finalType] = normalizeIoc(inputValue, detectedType);

    // Quick analysis only checks VirusTotal
    const vtResult = await checkVirusTotal(normalizedValue);
    const formattedVt = formatVirusTotal(vtResult);

    return res.status(200).json({
      input: inputValue,
      normalized_input: normalizedValue,
      type: finalType,
      type_description: getIocDescription(finalType),
      virustotal: formattedVt,
      quick_analysis: true
    });

  } catch (error) {
    console.error('Quick analysis error:', error);
    return res.status(500).json({
      detail: `Analysis failed: ${error.message}`,
      error_type: error.constructor.name
    });
  }
}

async function handleSources(req, res) {
  return res.status(200).json({
    sources: [
      { 
        name: 'VirusTotal', 
        type: 'multi-engine scanner',
        description: 'Analyzes suspicious files, domains, IPs and URLs to detect malware and automatically share them with the security community',
        supported_iocs: ['ip', 'domain', 'url', 'hash'],
        website: 'https://www.virustotal.com'
      },
      { 
        name: 'AbuseIPDB', 
        type: 'IP reputation database',
        description: 'Helps combat the spread of hackers, spammers, and abusive activity on the internet',
        supported_iocs: ['ip'],
        website: 'https://www.abuseipdb.com'
      },
      { 
        name: 'Shodan', 
        type: 'Internet device search',
        description: 'Search engine for Internet-connected devices',
        supported_iocs: ['ip'],
        website: 'https://www.shodan.io'
      },
      { 
        name: 'AlienVault OTX', 
        type: 'Threat intelligence platform',
        description: 'Open Threat Exchange is an open threat information sharing and analysis network',
        supported_iocs: ['ip', 'domain', 'hash'],
        website: 'https://otx.alienvault.com'
      },
      { 
        name: 'ThreatFox', 
        type: 'Malware IOC database',
        description: 'Platform for sharing IOCs associated with malware',
        supported_iocs: ['ip', 'domain', 'hash', 'threatfox_query'],
        website: 'https://threatfox.abuse.ch'
      },
      { 
        name: 'URLhaus', 
        type: 'Malware URL database',
        description: 'Project to collect and share URLs used for malware distribution',
        supported_iocs: ['hash', 'url'],
        website: 'https://urlhaus.abuse.ch'
      },
      { 
        name: 'MalwareBazaar', 
        type: 'Malware sample database',
        description: 'Project to collect and share malware samples',
        supported_iocs: ['hash'],
        website: 'https://bazaar.abuse.ch'
      },
      { 
        name: 'IPInfo', 
        type: 'IP geolocation service',
        description: 'Provides IP address data including geolocation, company, carrier details',
        supported_iocs: ['ip'],
        website: 'https://ipinfo.io'
      },
      { 
        name: 'URLScan', 
        type: 'URL analysis service',
        description: 'Free service to scan and analyze websites',
        supported_iocs: ['url', 'domain'],
        website: 'https://urlscan.io'
      }
    ],
    version: '2.0.0',
    timestamp: new Date().toISOString()
  });
}