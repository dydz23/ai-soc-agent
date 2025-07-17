// api/quick-analyze.js

import { detectInputType, validateIoc, getIocDescription } from '../utils/iocDetection.js';
import { formatVirusTotal, formatThreatFox } from '../utils/formatters.js';
import { SOCAnalystLLM } from '../utils/claude.js';
import { checkVirusTotal, checkIP, lookupThreatFox } from './threat-intel.js';

export default async function handler(req, res) {
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
        detail: "Must provide input value for quick analysis."
      });
    }
    
    // Detect and validate IOC type
    const inputType = detectInputType(inputValue);
    const [isValid, errorMessage] = validateIoc(inputValue, inputType);
    
    if (!isValid) {
      return res.status(400).json({
        detail: errorMessage,
        detected_type: inputType,
        type_description: getIocDescription(inputType)
      });
    }

    // Handle unsupported IOC types for quick analysis
    const unsupportedTypes = [
      "email", "cidr_ipv4", "cidr_ipv6", "registry_key", "file_path_windows", 
      "file_path_unix", "mutex", "user_agent", "bitcoin_address", "cve", 
      "asn", "yara_rule", "mac_address", "process_name", "port"
    ];
    
    if (unsupportedTypes.includes(inputType)) {
      return res.status(400).json({
        detail: `IOC type '${getIocDescription(inputType)}' is not supported for quick analysis.`,
        detected_type: inputType,
        type_description: getIocDescription(inputType),
        supported_types: ["ip", "domain", "url", "hash", "threatfox_query"]
      });
    }
    
    // Only use core sources for quick analysis to reduce latency
    const corePromises = [
      checkVirusTotal(inputValue),
      lookupThreatFox(inputValue)
    ];
    
    // Add AbuseIPDB for IP addresses only
    if (inputType === "ip" || inputType === "ipv4" || inputType === "ipv6") {
      corePromises.push(checkIP(inputValue));
    }

    const [vtResult, tfResult, abuseResult] = await Promise.allSettled(corePromises);

    const quickResults = {
      input: inputValue,
      type: inputType,
      type_description: getIocDescription(inputType),
      virustotal: formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message }),
      threatfox: formatThreatFox(tfResult.status === 'fulfilled' ? tfResult.value : { error: tfResult.reason?.message }),
      abuseipdb: abuseResult ? (abuseResult.status === 'fulfilled' ? abuseResult.value : { error: abuseResult.reason?.message }) : {}
    };
    
    // Quick SOC analysis with limited data
    const socAnalyst = new SOCAnalystLLM();
    const socAnalysis = await socAnalyst.generateSOCAnalysis(quickResults);
    
    // Calculate basic risk score for quick analysis
    let quickRiskScore = 0;
    let riskFactors = [];
    
    // VirusTotal quick scoring
    const vtData = quickResults.virustotal;
    if (vtData && vtData["Malicious Detections"]) {
      const maliciousCount = parseInt(vtData["Malicious Detections"]) || 0;
      if (maliciousCount > 0) {
        quickRiskScore += Math.min(maliciousCount * 10, 40);
        riskFactors.push(`${maliciousCount} malicious detections`);
      }
    }
    
    // AbuseIPDB quick scoring
    const abuseData = quickResults.abuseipdb;
    if (abuseData && abuseData["Abuse Score"]) {
      const abuseScore = parseInt(abuseData["Abuse Score"]) || 0;
      if (abuseScore > 25) {
        quickRiskScore += Math.min(abuseScore, 35);
        riskFactors.push(`${abuseScore}% abuse confidence`);
      }
    }
    
    // ThreatFox quick scoring
    const tfData = quickResults.threatfox;
    if (Array.isArray(tfData) && tfData.length > 0) {
      quickRiskScore += 25;
      riskFactors.push("Found in ThreatFox database");
    }
    
    // Determine risk level
    let riskLevel;
    if (quickRiskScore >= 70) riskLevel = "HIGH";
    else if (quickRiskScore >= 40) riskLevel = "MEDIUM";
    else if (quickRiskScore >= 15) riskLevel = "LOW";
    else riskLevel = "BENIGN";

    const response = {
      input: inputValue,
      type: inputType,
      type_description: getIocDescription(inputType),
      quick_analysis: true,
      analysis_sources: ["VirusTotal", "ThreatFox"],
      results: quickResults,
      soc_analysis: socAnalysis,
      summary: socAnalysis.llm_analysis,
      quick_assessment: {
        risk_score: quickRiskScore,
        risk_level: riskLevel,
        risk_factors: riskFactors,
        confidence: riskFactors.length > 0 ? "MEDIUM" : "LOW",
        recommendation: riskLevel === "HIGH" ? "BLOCK" : 
                      riskLevel === "MEDIUM" ? "INVESTIGATE" : 
                      riskLevel === "LOW" ? "MONITOR" : "ALLOW"
      },
      metadata: {
        analyst_version: "2.0-quick",
        analysis_time: new Date().toISOString(),
        confidence_level: socAnalysis.confidence_level,
        risk_level: socAnalysis.risk_assessment.level,
        risk_score: socAnalysis.risk_assessment.score,
        recommended_actions: socAnalysis.recommended_actions,
        analysis_timestamp: socAnalysis.timestamp,
        sources_queried: quickResults.abuseipdb && Object.keys(quickResults.abuseipdb).length > 0 ? 3 : 2,
        analysis_duration: "< 10 seconds"
      }
    };
    
    return res.status(200).json(response);
    
  } catch (error) {
    console.error('Quick analysis error:', error);
    return res.status(500).json({
      detail: `Quick analysis failed: ${error.message}`,
      error_type: error.constructor.name,
      timestamp: new Date().toISOString()
    });
  }
}