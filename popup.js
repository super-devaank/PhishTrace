console.log("PhishTrace V5 started");

const analyzeButton = document.getElementById("analyze");
const urlDisplay = document.getElementById("url");
const riskLevel = document.getElementById("riskLevel");
const riskScore = document.getElementById("riskScore");
const riskBar = document.getElementById("riskBar");
const findings = document.getElementById("findings");
const status = document.getElementById("status");

// Trusted brand reference list
const trustedBrands = {
  google: "google.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  amazon: "amazon.com",
  paypal: "paypal.com",
  facebook: "facebook.com",
  instagram: "instagram.com",
  youtube: "youtube.com",
  netflix: "netflix.com",
  whatsapp: "whatsapp.com",
  linkedin: "linkedin.com",
  samsung: "samsung.com",
  adobe: "adobe.com",
  dropbox: "dropbox.com",
  spotify: "spotify.com",
  flipkart: "flipkart.com",
  myntra: "myntra.com",
  swiggy: "swiggy.com",
  zomato: "zomato.com",
  paytm: "paytm.com",
  phonepe: "phonepe.com",
  hdfcbank: "hdfcbank.com",
  icicibank: "icicibank.com",
  axisbank: "axisbank.com"
};

// Common multi-part public suffixes
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk",
  "com.au", "net.au", "org.au",
  "co.in", "firm.in", "net.in", "org.in",
  "co.jp", "ne.jp", "or.jp",
  "co.nz", "net.nz", "org.nz",
  "com.br", "com.sg", "com.cn",
  "co.za", "com.mx", "com.tr"
]);

// Extract the registrable-domain candidate
function getDomainInfo(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const labels = host.split(".").filter(Boolean);

  // Handle IPv4 addresses separately
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    return {
      hostname: host,
      registrableDomain: host,
      domainLabel: host,
      subdomains: []
    };
  }

  if (labels.length < 2) {
    return {
      hostname: host,
      registrableDomain: host,
      domainLabel: labels[0] || "",
      subdomains: []
    };
  }

  const lastTwo = labels.slice(-2).join(".");
  const suffixLength = MULTI_PART_SUFFIXES.has(lastTwo) ? 2 : 1;

  if (labels.length <= suffixLength) {
    return {
      hostname: host,
      registrableDomain: host,
      domainLabel: labels[0] || "",
      subdomains: []
    };
  }

  const domainIndex = labels.length - suffixLength - 1;

  return {
    hostname: host,
    registrableDomain: labels.slice(domainIndex).join("."),
    domainLabel: labels[domainIndex],
    subdomains: labels.slice(0, domainIndex)
  };
}

// Detect Unicode characters that may imitate ordinary Latin letters
function detectHomograph(hostname) {
  const warnings = [];

  const hasNonASCII = /[^\x00-\x7F]/.test(hostname);

  if (!hasNonASCII) {
    return warnings;
  }

  warnings.push(
    "Non-ASCII characters detected in the domain. Some characters may visually resemble ordinary letters."
  );

  return warnings;
}

// Calculate spelling similarity
function editDistance(a, b) {
  const dp = Array.from(
    { length: a.length + 1 },
    () => Array(b.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) {
    dp[i][0] = i;
  }

  for (let j = 0; j <= b.length; j++) {
    dp[0][j] = j;
  }

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;

      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }

  return dp[a.length][b.length];
}

// Detect brand impersonation
function detectBrandImpersonation(hostname) {
  const info = getDomainInfo(hostname);
  const host = info.hostname;
  const domainLabel = info.domainLabel;

  const warnings = [];

  for (const [brand, officialDomain] of Object.entries(trustedBrands)) {
    const isOfficial =
      host === officialDomain ||
      host.endsWith("." + officialDomain);

    if (isOfficial) continue;

    if (host.includes(brand)) {
      warnings.push(
        `Possible ${brand} impersonation: the domain contains the brand name but is not its official domain.`
      );
      continue;
    }

    const normalizedLabel = domainLabel.replace(/-/g, "");

    if (
      brand.length >= 5 &&
      editDistance(normalizedLabel, brand) <= 1
    ) {
      warnings.push(
        `Possible ${brand} spelling imitation detected.`
      );
    }
  }

  return warnings;
}

// Main URL analysis
function analyzeURL(input) {
  let url;

  try {
    url = new URL(input);
  } catch {
    return {
      score: 0,
      level: "Unable to analyze",
      warnings: ["The URL could not be parsed."]
    };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return {
      score: 0,
      level: "Unsupported page",
      warnings: ["Only HTTP and HTTPS websites can be analyzed."]
    };
  }

  let score = 0;
  const warnings = [];

  function addFinding(points, message) {
    score += points;
    warnings.push(message);
  }

  const hostname = url.hostname.toLowerCase();
  const fullURL = url.href.toLowerCase();

  const domainInfo = getDomainInfo(hostname);
  const labels = hostname.split(".");
  const domainLabel = domainInfo.domainLabel;

  // 1. Brand impersonation
const brandWarnings = detectBrandImpersonation(hostname);

for (const warning of brandWarnings) {
  addFinding(30, warning);
}

// 2. Unicode homograph detection
const homographWarnings = detectHomograph(hostname);

for (const warning of homographWarnings) {
  addFinding(20, warning);
}

  // 2. HTTP instead of HTTPS
  if (url.protocol === "http:") {
    addFinding(
      10,
      "The website does not use HTTPS encryption."
    );
  }

  // 3. Suspicious keywords
  const suspiciousWords = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "wallet",
    "banking",
    "password",
    "signin",
    "confirm",
    "recovery"
  ];

  const foundWords = suspiciousWords.filter(word =>
    fullURL.includes(word)
  );

  if (foundWords.length > 0) {
    addFinding(
      12,
      `Suspicious keywords found: ${foundWords.join(", ")}.`
    );
  }

  // 4. Excessive URL length
  if (url.href.length > 100) {
    addFinding(8, "Unusually long URL detected.");
  }

  // 5. IP address instead of domain name
  const ipv4Pattern =
    /^(?:\d{1,3}\.){3}\d{1,3}$/;

  if (ipv4Pattern.test(hostname)) {
    const validIP = hostname
      .split(".")
      .every(part => Number(part) <= 255);

    if (validIP) {
      addFinding(
        25,
        "The website uses an IP address instead of a normal domain name."
      );
    }
  }

  // 6. @ symbol or embedded credentials
  if (url.username || url.password || input.includes("@")) {
    addFinding(
      25,
      "The URL contains an @ symbol or embedded login credentials."
    );
  }

  // 7. Punycode domain
  if (hostname.includes("xn--")) {
    addFinding(
      20,
      "Punycode detected in the domain. This can be used for lookalike characters."
    );
  }

  // 8. Too many subdomains
  if (labels.length > 4) {
    addFinding(
      12,
      "The domain contains an unusually large number of subdomain labels."
    );
  }

  // 9. Multiple hyphens
  const hyphenCount =
    (domainLabel.match(/-/g) || []).length;

  if (hyphenCount >= 2) {
    addFinding(
      10,
      "The main domain contains multiple hyphens."
    );
  }

  // 10. Unusual domain length
  if (domainLabel.length > 25) {
    addFinding(
      10,
      "The main domain name is unusually long."
    );
  }

  // 11. Unusual port
  if (url.port && !["80", "443"].includes(url.port)) {
    addFinding(
      8,
      "The website uses a non-standard port number."
    );
  }

  // 12. Encoded URL characters
  if (/%[0-9a-f]{2}/i.test(url.href)) {
    addFinding(
      8,
      "Encoded characters were detected in the URL."
    );
  }

  // Final score
  score = Math.min(score, 100);

  let level;

  if (score >= 60) {
    level = "HIGH RISK";
  } else if (score >= 25) {
    level = "MEDIUM RISK";
  } else {
    level = "LOW RISK";
  }

  if (warnings.length === 0) {
    warnings.push(
      "No common suspicious URL indicators were detected."
    );
  }

  return {
    score,
    level,
    warnings
  };
}

// Display results
function displayResults(result) {
  riskScore.innerHTML = `${result.score}<small>/100</small>`;
  riskLevel.textContent = result.level;

  riskBar.style.width = `${result.score}%`;

  if (result.score >= 60) {
    riskBar.style.background = "#ff5263";
    riskScore.style.color = "#ff5263";
    riskLevel.style.color = "#ff5263";
  } else if (result.score >= 25) {
    riskBar.style.background = "#ffb84d";
    riskScore.style.color = "#ffb84d";
    riskLevel.style.color = "#ffb84d";
  } else {
    riskBar.style.background = "#50e3c2";
    riskScore.style.color = "#50e3c2";
    riskLevel.style.color = "#50e3c2";
  }

  findings.replaceChildren();

  result.warnings.forEach(warning => {
    const item = document.createElement("li");
    item.textContent = warning;
    findings.appendChild(item);
  });

  status.textContent = "SCAN COMPLETE";
}

// Scan button
analyzeButton.addEventListener("click", async () => {
  analyzeButton.disabled = true;
  analyzeButton.textContent = "SCANNING...";
  status.textContent = "ANALYZING";

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    const currentTab = tabs[0];

    if (!currentTab || !currentTab.url) {
      throw new Error("Could not access the current tab URL.");
    }

    urlDisplay.textContent = currentTab.url;

    const result = analyzeURL(currentTab.url);

    displayResults(result);

  } catch (error) {
    riskLevel.textContent = "SCAN FAILED";
    riskScore.textContent = "--/100";
    riskBar.style.width = "0%";
    status.textContent = "ERROR";

    findings.replaceChildren();

    const item = document.createElement("li");
    item.textContent = error.message;
    findings.appendChild(item);

    console.error("PhishTrace error:", error);

  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = "SCAN WEBSITE";
  }
});