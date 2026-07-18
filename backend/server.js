// ============================================================
// FILE: server.js  —  Advanced PhishGuard AI Backend
// Stack: Node.js + Express
// PORT: 5000
// ============================================================

const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend/dist')));

// ============================================================
// VULNERABILITY DATABASE — Detailed CVE-style threat intel
// ============================================================
const VULNERABILITY_DB = {
  NO_HTTPS: {
    id: 'VLN-001',
    type: 'Transport Security',
    name: 'Unencrypted HTTP Connection',
    severity: 'HIGH',
    cvss: 7.5,
    description: 'The URL uses HTTP instead of HTTPS, meaning all data transmitted between your browser and this server is sent in plaintext. Attackers on the same network can intercept login credentials, session tokens, and personal data.',
    cause: 'Missing SSL/TLS certificate or intentional removal to avoid detection',
    impact: 'Credential theft, session hijacking, man-in-the-middle attacks',
    mitigation: 'Legitimate sites always use HTTPS. Avoid entering any data on this page.',
    cweId: 'CWE-319',
    technique: 'T1040 - Network Sniffing',
    score: 20
  },
  SUSPICIOUS_KEYWORD: {
    id: 'VLN-002',
    type: 'Social Engineering',
    name: 'Phishing Keyword Detected',
    severity: 'MEDIUM',
    cvss: 5.9,
    description: 'The URL contains keywords commonly used in phishing campaigns to create urgency or mimic legitimate services (e.g., "login", "verify", "secure", "account", "password", "banking").',
    cause: 'Attackers embed trust-inducing words in URLs to trick users into believing the site is legitimate',
    impact: 'Users may be deceived into entering credentials or sensitive information',
    mitigation: 'Verify the domain carefully. Never click emailed links — go directly to the official site.',
    cweId: 'CWE-1021',
    technique: 'T1566.002 - Spearphishing Link',
    score: 15
  },
  AT_SIGN: {
    id: 'VLN-003',
    type: 'URL Obfuscation',
    name: 'URL Authority Bypass via @ Symbol',
    severity: 'CRITICAL',
    cvss: 9.1,
    description: 'The URL contains the @ symbol. In RFC-3986, anything before @ in a URL is treated as credentials. Browsers ignore this portion and navigate to the actual domain after @. Example: http://google.com@evil.com takes you to evil.com, not google.com.',
    cause: 'Exploits RFC-3986 URL parsing to disguise the true destination',
    impact: 'Complete destination masking — user believes they visit a trusted site but lands on attacker server',
    mitigation: 'Immediately avoid this URL. This is an almost certain phishing or redirect attack.',
    cweId: 'CWE-601',
    technique: 'T1598.003 - Spearphishing Link',
    score: 40
  },
  LONG_URL: {
    id: 'VLN-004',
    type: 'Obfuscation',
    name: 'Excessively Long URL',
    severity: 'LOW',
    cvss: 3.1,
    description: 'Phishing URLs are often made very long to hide the real domain name in the middle or end, making it harder for users to identify the true destination.',
    cause: 'Deliberate padding of URL with fake path segments to obscure malicious domain',
    impact: 'Users may focus on recognizable words and miss the malicious domain portion',
    mitigation: 'Look at the domain (between // and the first /) carefully.',
    cweId: 'CWE-116',
    technique: 'T1036 - Masquerading',
    score: 10
  },
  SUSPICIOUS_TLD: {
    id: 'VLN-005',
    type: 'Domain Intelligence',
    name: 'High-Risk Top-Level Domain',
    severity: 'HIGH',
    cvss: 6.8,
    description: 'The URL uses a top-level domain (TLD) frequently associated with phishing, spam, and malware campaigns (.xyz, .top, .click, .info, .biz, .online). These TLDs are cheap or free, making them attractive to attackers.',
    cause: 'Low-cost registration of high-risk TLDs for disposable phishing infrastructure',
    impact: 'Increased probability the site is fraudulent or associated with malicious campaigns',
    mitigation: 'Trusted services use established TLDs (.com, .org, .gov, .edu). Treat high-risk TLDs with extreme caution.',
    cweId: 'CWE-345',
    technique: 'T1583.001 - Acquire Infrastructure: Domains',
    score: 20
  },
  IP_ADDRESS: {
    id: 'VLN-006',
    type: 'Domain Masking',
    name: 'Direct IP Address URL',
    severity: 'HIGH',
    cvss: 7.2,
    description: 'The URL uses a raw IP address instead of a domain name. Legitimate websites use registered domain names. Phishing sites often use IPs to avoid domain blacklists and WHOIS lookups.',
    cause: 'Attacker hosts phishing kit on a VPS/cloud server using only its IP to evade DNS-based detection',
    impact: 'Harder to trace, block, or report. No certificate validation possible.',
    mitigation: 'Never trust URLs with raw IP addresses for any sensitive operation.',
    cweId: 'CWE-350',
    technique: 'T1583.004 - Acquire Infrastructure: Server',
    score: 25
  },
  DOUBLE_SLASH: {
    id: 'VLN-007',
    type: 'URL Obfuscation',
    name: 'Double Slash Redirect Trick',
    severity: 'MEDIUM',
    cvss: 5.3,
    description: 'The URL contains double slashes (//). Some phishing URLs use this pattern to confuse parsers or create open redirects that appear legitimate.',
    cause: 'Exploiting browser/server URL normalization to redirect users unexpectedly',
    impact: 'Unintended redirects to malicious destinations',
    mitigation: 'Be cautious of URLs with unusual formatting patterns.',
    cweId: 'CWE-601',
    technique: 'T1192 - Spearphishing Link',
    score: 10
  },
  SUBDOMAIN_ABUSE: {
    id: 'VLN-008',
    type: 'Domain Spoofing',
    name: 'Trusted Brand in Subdomain',
    severity: 'CRITICAL',
    cvss: 8.7,
    description: 'The URL contains a well-known brand name (Google, PayPal, Apple, Microsoft, Amazon, Facebook, Netflix, etc.) in the subdomain while the actual domain is different. Example: paypal.secure-login.xyz — the real domain is secure-login.xyz, not paypal.',
    cause: 'Domain spoofing: attacker registers a new domain and uses the trusted brand as a subdomain to deceive users',
    impact: 'Extremely convincing phishing — users see "paypal" in the URL and trust it',
    mitigation: 'Always check the domain (last two parts before the TLD), not the full URL or subdomain.',
    cweId: 'CWE-346',
    technique: 'T1434 - Domain Spoofing',
    score: 35
  },
  ENCODED_CHARS: {
    id: 'VLN-009',
    type: 'Obfuscation',
    name: 'URL Encoding Obfuscation',
    severity: 'MEDIUM',
    cvss: 5.0,
    description: 'The URL contains percent-encoded characters (%XX). While normal in some contexts, phishing URLs use heavy encoding to hide keywords that would otherwise trigger security filters.',
    cause: 'Bypass URL-based security scanners by encoding blacklisted words',
    impact: 'Evasion of email filters, web proxies, and security tools',
    mitigation: 'Decode the URL before visiting. Use a URL decoder tool to reveal hidden content.',
    cweId: 'CWE-116',
    technique: 'T1027 - Obfuscated Files or Information',
    score: 15
  },
  HOMOGRAPH: {
    id: 'VLN-010',
    type: 'Visual Spoofing',
    name: 'Possible Homograph/Typosquat Attack',
    severity: 'HIGH',
    cvss: 7.0,
    description: 'The domain contains character combinations that may indicate typosquatting (e.g., "g00gle", "paypa1", "rn" instead of "m") or punycode homograph attacks where Unicode characters resemble ASCII letters.',
    cause: 'Attacker registers domains that look visually identical to legitimate ones',
    impact: 'Users copy-paste or misread URLs and end up on attacker-controlled sites',
    mitigation: 'Type important URLs directly into the browser rather than clicking links.',
    cweId: 'CWE-1021',
    technique: 'T1036.005 - Match Legitimate Name or Location',
    score: 20
  }
};

// ============================================================
// DETECTION ENGINES — Simulates multi-engine scan like VirusTotal
// ============================================================
const ENGINES = [
  { name: 'PhishTank AI', vendor: 'PhishGuard Labs', version: 'v3.2.1' },
  { name: 'URLhaus Scanner', vendor: 'Abuse.ch', version: 'v2.1.0' },
  { name: 'SafeBrowse ML', vendor: 'Google', version: 'v5.8.3' },
  { name: 'OpenPhish DB', vendor: 'OpenPhish', version: 'v1.9.2' },
  { name: 'ThreatIntel Pro', vendor: 'CrowdStrike', version: 'v4.0.1' },
  { name: 'MalURL Detect', vendor: 'Kaspersky', version: 'v7.3.0' },
  { name: 'WebRisk API', vendor: 'Microsoft', version: 'v2.4.1' },
  { name: 'ZeuS Tracker', vendor: 'Emerging Threats', version: 'v1.5.8' },
  { name: 'FortiGuard Web', vendor: 'Fortinet', version: 'v6.2.0' },
  { name: 'Avast DeepURL', vendor: 'Avast', version: 'v9.1.4' },
  { name: 'Norton SafeWeb', vendor: 'NortonLifeLock', version: 'v3.7.2' },
  { name: 'McAfee WebAdv', vendor: 'McAfee', version: 'v5.4.1' },
  { name: 'Bitdefender AI', vendor: 'Bitdefender', version: 'v8.0.3' },
  { name: 'ESET LiveGrid', vendor: 'ESET', version: 'v4.2.7' },
  { name: 'Trend Micro WRS', vendor: 'Trend Micro', version: 'v2.9.1' },
  { name: 'Sophos Intelix', vendor: 'Sophos', version: 'v3.1.5' },
];

// ============================================================
// PORT SCANNER — delegates to Python app1.py
// ============================================================
const PYTHON_SCANNER = path.join(__dirname, 'app1.py');

function scanPorts(hostname) {
  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const py = spawn('python', [PYTHON_SCANNER, '--target', hostname, '--json'], {
      timeout: 15000,
    });
    let stdout = '';
    let stderr = '';
    py.stdout.on('data', d => { stdout += d.toString(); });
    py.stderr.on('data', d => { stderr += d.toString(); });
    py.on('close', (code) => {
      try {
        const parsed = JSON.parse(stdout.trim());
        // Normalise to the shape the frontend expects
        const ports = (parsed.ports || []).map(p => ({
          port:        p.port,
          service:     p.service,
          description: p.description,
          risk:        p.risk,
          tip:         p.tip,
          exploit:     p.exploit,
          open:        p.open,
          state:       p.state,
        }));
        resolve(ports);
      } catch (e) {
        console.error('[Port scan] Python parse error:', e.message, '| stderr:', stderr.slice(0, 200));
        resolve([]);
      }
    });
    py.on('error', (err) => {
      console.error('[Port scan] Failed to spawn Python:', err.message);
      resolve([]);
    });
  });
}

// ============================================================
// CORE AI DETECTION FUNCTION
// ============================================================
function analyzeURL(url) {
  let totalScore = 0;
  const detectedVulnerabilities = [];
  const keywordHits = [];

  // --- Rule 1: HTTPS check ---
  if (!url.startsWith('https://')) {
    totalScore += VULNERABILITY_DB.NO_HTTPS.score;
    detectedVulnerabilities.push({ ...VULNERABILITY_DB.NO_HTTPS });
  }

  // --- Rule 2: Suspicious keywords ---
  const badWords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'password', 'signin', 'wallet', 'confirm', 'authenticate', 'recover', 'reset'];
  const foundKeywords = badWords.filter(word => url.toLowerCase().includes(word));
  if (foundKeywords.length > 0) {
    const vuln = { ...VULNERABILITY_DB.SUSPICIOUS_KEYWORD };
    vuln.name = `Phishing Keyword(s) Detected: "${foundKeywords.join('", "')}"`;
    vuln.score = Math.min(foundKeywords.length * 15, 45);
    totalScore += vuln.score;
    detectedVulnerabilities.push(vuln);
    keywordHits.push(...foundKeywords);
  }

  // --- Rule 3: @ symbol ---
  if (url.includes('@')) {
    totalScore += VULNERABILITY_DB.AT_SIGN.score;
    detectedVulnerabilities.push({ ...VULNERABILITY_DB.AT_SIGN });
  }

  // --- Rule 4: Long URL ---
  if (url.length > 75) {
    const vuln = { ...VULNERABILITY_DB.LONG_URL };
    vuln.name = `Excessively Long URL (${url.length} characters)`;
    totalScore += vuln.score;
    detectedVulnerabilities.push(vuln);
  }

  // --- Rule 5: Suspicious TLD ---
  const badTLDs = ['.xyz', '.top', '.click', '.info', '.biz', '.online', '.site', '.pw', '.gq', '.cf', '.tk', '.ml'];
  const matchedTLD = badTLDs.find(d => url.toLowerCase().includes(d));
  if (matchedTLD) {
    const vuln = { ...VULNERABILITY_DB.SUSPICIOUS_TLD };
    vuln.name = `High-Risk TLD Detected: "${matchedTLD}"`;
    totalScore += vuln.score;
    detectedVulnerabilities.push(vuln);
  }

  // --- Rule 6: Raw IP address ---
  const ipPattern = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
  if (ipPattern.test(url)) {
    totalScore += VULNERABILITY_DB.IP_ADDRESS.score;
    detectedVulnerabilities.push({ ...VULNERABILITY_DB.IP_ADDRESS });
  }

  // --- Rule 7: Double slash after domain ---
  const doubleSlash = url.replace('https://', '').replace('http://', '').includes('//');
  if (doubleSlash) {
    totalScore += VULNERABILITY_DB.DOUBLE_SLASH.score;
    detectedVulnerabilities.push({ ...VULNERABILITY_DB.DOUBLE_SLASH });
  }

  // --- Rule 8: Subdomain brand abuse ---
  const trustedBrands = ['google', 'paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'netflix', 'instagram', 'twitter', 'ebay', 'chase', 'wellsfargo', 'citibank', 'bankofamerica'];
  let detectedDomain = '';
  try { detectedDomain = new URL(url.startsWith('http') ? url : 'http://' + url).hostname; } catch {}
  const parts = detectedDomain.split('.');
  if (parts.length > 2) {
    const subdomain = parts.slice(0, -2).join('.');
    const rootDomain = parts.slice(-2).join('.');
    const brandFound = trustedBrands.find(b => subdomain.toLowerCase().includes(b) && !rootDomain.toLowerCase().includes(b));
    if (brandFound) {
      const vuln = { ...VULNERABILITY_DB.SUBDOMAIN_ABUSE };
      vuln.name = `Trusted Brand "${brandFound}" Abused in Subdomain`;
      vuln.description = vuln.description + ` Detected: "${brandFound}" appears in subdomain but the real domain is "${rootDomain}".`;
      totalScore += vuln.score;
      detectedVulnerabilities.push(vuln);
    }
  }

  // --- Rule 9: URL encoding ---
  if (/%[0-9a-fA-F]{2}/.test(url)) {
    totalScore += VULNERABILITY_DB.ENCODED_CHARS.score;
    detectedVulnerabilities.push({ ...VULNERABILITY_DB.ENCODED_CHARS });
  }

  // --- Rule 10: Homograph/typosquat ---
  const homographPatterns = ['0' , '1', 'rn', 'vv', 'cl'];
  const domainOnly = detectedDomain.replace(/\./g, '');
  const homographHit = homographPatterns.some(p => domainOnly.includes(p) && domainOnly.length > 4);
  if (homographHit && totalScore > 10) {
    totalScore += VULNERABILITY_DB.HOMOGRAPH.score;
    detectedVulnerabilities.push({ ...VULNERABILITY_DB.HOMOGRAPH });
  }

  // Cap score
  totalScore = Math.min(totalScore, 99);

  // --- Determine label ---
  let label, riskLevel;
  if (totalScore >= 40) {
    label = 'PHISHING';
    riskLevel = 'CRITICAL';
  } else if (totalScore >= 20) {
    label = 'SUSPICIOUS';
    riskLevel = 'MEDIUM';
  } else {
    label = 'SAFE';
    riskLevel = 'LOW';
  }

  // --- Generate engine results ---
  const engineResults = ENGINES.map(engine => {
    let detected = false;
    let engineResult = 'Clean';
    if (label === 'PHISHING') {
      detected = Math.random() > 0.3; // 70% engines flag phishing
    } else if (label === 'SUSPICIOUS') {
      detected = Math.random() > 0.65; // 35% engines flag suspicious
    } else {
      detected = Math.random() > 0.97; // ~3% false positive
    }
    if (detected) {
      const categories = ['phishing', 'malware', 'suspicious', 'spam', 'malicious'];
      engineResult = categories[Math.floor(Math.random() * (label === 'PHISHING' ? 2 : categories.length))];
    }
    return {
      ...engine,
      detected,
      result: engineResult,
      category: detected ? engineResult : 'clean',
      scanTime: (Math.random() * 800 + 100).toFixed(0) + 'ms'
    };
  });

  const detectedCount = engineResults.filter(e => e.detected).length;
  const cleanCount = ENGINES.length - detectedCount;

  // --- URL metadata ---
  let urlMeta = { protocol: '', domain: '', path: '', port: '', tld: '' };
  try {
    const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    urlMeta = {
      protocol: parsed.protocol,
      domain: parsed.hostname,
      path: parsed.pathname + parsed.search,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      tld: '.' + parsed.hostname.split('.').pop()
    };
  } catch {}

  return {
    url,
    label,
    riskLevel,
    score: totalScore,
    message: label === 'PHISHING'
      ? '🚨 HIGH RISK: This URL exhibits multiple phishing indicators!'
      : label === 'SUSPICIOUS'
        ? '⚠️ MEDIUM RISK: This URL shows suspicious patterns. Proceed with caution.'
        : '✅ LOW RISK: No significant threats detected. Appears safe.',
    vulnerabilities: detectedVulnerabilities,
    engines: engineResults,
    engineSummary: {
      total: ENGINES.length,
      detected: detectedCount,
      clean: cleanCount,
      detectionRate: Math.round((detectedCount / ENGINES.length) * 100)
    },
    urlMeta,
    scanTimestamp: new Date().toISOString(),
    scanDuration: (Math.random() * 1200 + 800).toFixed(0),
    // Legacy compat
    reasons: detectedVulnerabilities.map(v => v.name),
    isPhishing: label === 'PHISHING'
  };
}

// ============================================================
// API ROUTES
// ============================================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'online', engines: ENGINES.length, timestamp: new Date().toISOString() });
});

// Login
const VALID_CREDENTIALS = { username: 'dhruvpg', password: 'dhpriay@47' };

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  if (username === VALID_CREDENTIALS.username && password === VALID_CREDENTIALS.password) {
    return res.json({ success: true, message: 'Login successful' });
  }
  return res.status(401).json({ error: 'Invalid username or password.' });
});

// Main detection endpoint
app.post('/api/check', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Please provide a URL to check.' });
  console.log('Scanning URL:', url);
  const result = analyzeURL(url);

  // --- Port scan (single pass) ---
  let allPorts = [];
  try {
    const hostname = result.urlMeta.domain ||
      (() => { try { return new URL(url.startsWith('http') ? url : 'http://' + url).hostname; } catch { return ''; } })();
    if (hostname) {
      allPorts = await scanPorts(hostname);
    }
  } catch (e) {
    console.error('Port scan error:', e.message);
  }

  result.allPorts  = allPorts;
  result.openPorts = allPorts.filter(p => p.open);

  console.log(`Result: ${result.label} | Score: ${result.score} | Vulns: ${result.vulnerabilities.length} | Engines flagged: ${result.engineSummary.detected}/${result.engineSummary.total} | Open ports: ${result.openPorts.length}`);
  res.json(result);
});

// Serve React app for all other routes
app.get('/*path', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
});

const server = app.listen(PORT, () => {
  console.log('\n==============================================');
  console.log('  🛡️  PhishGuard AI — Running');
  console.log('==============================================');
  console.log(`  Backend  API  →  http://localhost:${PORT}`);
  console.log(`  Frontend App  →  http://localhost:5173`);
  console.log(`  Detection Engines: ${ENGINES.length}`);
  console.log(`  Vulnerability DB:  ${Object.keys(VULNERABILITY_DB).length} signatures`);
  console.log('==============================================\n');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[ERROR] Port ${PORT} is already in use!`);
    console.error(`  → Kill the process using port ${PORT} and run again.`);
    console.error(`  → On Windows: netstat -ano | findstr :${PORT}  then  taskkill /PID <PID> /F`);
    process.exit(1);
  } else {
    throw err;
  }
});
