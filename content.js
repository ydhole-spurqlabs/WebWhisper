// Content script that runs on web pages
// This script analyzes the page for security vulnerabilities

// Variables to track scan state
let isScanning = false;
let isPaused = false;
let scanTimer = null;
let isBackgroundScan = false;

// Listen for messages from the popup or background script
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "scan") {
    // Start a new scan initiated from the popup
    if (!isScanning) {
      isScanning = true;
      isPaused = false;
      isBackgroundScan = false;
      startScan(sendResponse);
      return true; // Keep the messaging channel open for async response
    }
  } else if (request.action === "scanInBackground") {
    // Start a scan initiated from the background script
    if (!isScanning) {
      isScanning = true;
      isPaused = false;
      isBackgroundScan = true;
      startBackgroundScan(sendResponse);
      return true; // Keep the messaging channel open for async response
    } else {
      // If already scanning, just return current status
      sendResponse({
        status: "scanning",
        isBackgroundScan: isBackgroundScan
      });
    }
  } else if (request.action === "pause") {
    // Pause an ongoing scan
    if (isScanning && !isPaused) {
      isPaused = true;
      if (scanTimer) {
        clearTimeout(scanTimer);
      }
      sendResponse({status: "paused"});
    }
  } else if (request.action === "continue") {
    // Continue a paused scan
    if (isScanning && isPaused) {
      isPaused = false;
      if (isBackgroundScan) {
        continueBackgroundScan(sendResponse);
      } else {
        continueScan(sendResponse);
      }
      return true; // Keep the messaging channel open for async response
    }
  } else if (request.action === "stop") {
    // Stop an ongoing scan
    if (isScanning) {
      isScanning = false;
      isPaused = false;
      if (scanTimer) {
        clearTimeout(scanTimer);
      }
      // Save partial results if needed
      savePartialResults();
      sendResponse({status: "stopped"});
    }
  }
  return true; // Required to use sendResponse asynchronously
});

// Function to start a security scan initiated from popup
function startScan(callback) {
  // Clear previous results
  let vulnerabilities = [];
  
  // In a real extension, we might scan the page in chunks to not block the UI
  scanTimer = setTimeout(() => {
    if (isScanning && !isPaused) {
      // Perform the actual scan
      vulnerabilities = scanForVulnerabilities();
      
      // Send results to background script for storage
      chrome.runtime.sendMessage({
        action: "saveVulnerability",
        data: vulnerabilities
      });
      
      // Complete the scan
      isScanning = false;
      
      // Send results back to popup
      if (callback) {
        callback({vulnerabilities: vulnerabilities});
      }
    }
  }, 1000);
}

// Function to start a security scan in the background
function startBackgroundScan(callback) {
  // In a background scan, we want to be less intrusive 
  // and scan more gradually to not impact performance
  scanTimer = setTimeout(() => {
    if (isScanning && !isPaused) {
      // Perform a lightweight scan
      const vulnerabilities = scanForVulnerabilities(true);
      
      // Send results directly to background script
      chrome.runtime.sendMessage({
        action: "saveVulnerability",
        data: vulnerabilities
      });
      
      // Complete the scan
      isScanning = false;
      
      // Send results back to caller
      if (callback) {
        callback({vulnerabilities: vulnerabilities});
      }
    }
  }, 500); // Faster scan for background operation
}

// Function to continue a paused scan
function continueScan(callback) {
  scanTimer = setTimeout(() => {
    if (isScanning && !isPaused) {
      // For demo, just do a full scan when continuing
      const vulnerabilities = scanForVulnerabilities();
      
      // Send results to background script for storage
      chrome.runtime.sendMessage({
        action: "saveVulnerability",
        data: vulnerabilities
      });
      
      // Complete the scan
      isScanning = false;
      
      // Send results back to popup
      if (callback) {
        callback({vulnerabilities: vulnerabilities});
      }
    }
  }, 1000);
}

// Function to continue a paused background scan
function continueBackgroundScan(callback) {
  scanTimer = setTimeout(() => {
    if (isScanning && !isPaused) {
      // For background scanning, use the lighter scan option
      const vulnerabilities = scanForVulnerabilities(true);
      
      // Send results to background script
      chrome.runtime.sendMessage({
        action: "saveVulnerability",
        data: vulnerabilities
      });
      
      // Complete the scan
      isScanning = false;
      
      // Send results back
      if (callback) {
        callback({vulnerabilities: vulnerabilities});
      }
    }
  }, 500);
}

// Function to save partial results when a scan is stopped
function savePartialResults() {
  // In a real extension, we'd save what was scanned so far
  // For demo purposes, we'll just perform a quick scan
  const partialVulnerabilities = scanForVulnerabilities(true);
  
  // Save to background script
  chrome.runtime.sendMessage({
    action: "saveVulnerability",
    data: partialVulnerabilities
  });
}

// Function to scan the page for security vulnerabilities
// If isBackground is true, perform a lighter scan
function scanForVulnerabilities(isBackground = false) {
  const vulnerabilities = [];
  
  // For background scans, we might want to limit the scan scope
  // to reduce performance impact on the user's browsing experience
  
  // Check for insecure form submission
  checkInsecureForms(vulnerabilities);
  
  // Check for mixed content
  checkMixedContent(vulnerabilities);
  
  // Only perform these more intensive checks if not in background mode
  // or randomly in background mode to avoid impacting browsing experience
  if (!isBackground || Math.random() < 0.3) {
    // Check for vulnerable libraries
    checkVulnerableLibraries(vulnerabilities);

    // Check for sensitive information in HTML
    checkSensitiveInfo(vulnerabilities);
  }
  
  // Return found vulnerabilities
  return vulnerabilities;
}

// Check if forms are submitting data over insecure HTTP
function checkInsecureForms(vulnerabilities) {
  const forms = document.getElementsByTagName('form');
  
  for (let i = 0; i < forms.length; i++) {
    const form = forms[i];
    const action = form.getAttribute('action');
    
    if (action && action.startsWith('http:')) {
      vulnerabilities.push({
        name: 'Insecure Form Submission',
        description: 'This page contains a form that submits data over unencrypted HTTP, which could allow attackers to intercept sensitive information.',
        severity: 'High',
        location: `Form with action="${action}"`
      });
    }
  }
}

// Check for mixed content (HTTPS page loading HTTP resources)
function checkMixedContent(vulnerabilities) {
  if (window.location.protocol === 'https:') {
    const scripts = document.getElementsByTagName('script');
    const links = document.getElementsByTagName('link');
    const images = document.getElementsByTagName('img');
    
    // Check scripts
    for (let i = 0; i < scripts.length; i++) {
      const src = scripts[i].getAttribute('src');
      if (src && src.startsWith('http:')) {
        vulnerabilities.push({
          name: 'Mixed Content: Script',
          description: 'This secure page is loading a script over an insecure connection, which could allow attackers to modify page behavior.',
          severity: 'High',
          location: src
        });
      }
    }
    
    // Check stylesheets
    for (let i = 0; i < links.length; i++) {
      if (links[i].rel === 'stylesheet') {
        const href = links[i].getAttribute('href');
        if (href && href.startsWith('http:')) {
          vulnerabilities.push({
            name: 'Mixed Content: Stylesheet',
            description: 'This secure page is loading a stylesheet over an insecure connection, which could allow attackers to modify page appearance.',
            severity: 'Medium',
            location: href
          });
        }
      }
    }
    
    // Check images
    for (let i = 0; i < images.length; i++) {
      const src = images[i].getAttribute('src');
      if (src && src.startsWith('http:')) {
        vulnerabilities.push({
          name: 'Mixed Content: Image',
          description: 'This secure page is loading an image over an insecure connection, which may trigger browser warnings.',
          severity: 'Low',
          location: src
        });
      }
    }
  }
}

// Simple check for known vulnerable library versions
function checkVulnerableLibraries(vulnerabilities) {
  // List of known vulnerable library signatures
  const vulnerableLibraries = [
    { name: 'jQuery', version: '<3.0.0', regex: /jQuery\s+v([0-2]\.[0-9]+\.[0-9]+)/ },
    { name: 'Angular', version: '<1.6.0', regex: /angular.*?([0-1]\.[0-5]\.[0-9]+)/ }
  ];
  
  // Get all scripts in the page
  const scripts = document.getElementsByTagName('script');
  const scriptContents = document.body.innerHTML;
  
  // Check each vulnerable library signature
  vulnerableLibraries.forEach(lib => {
    if (lib.regex.test(scriptContents)) {
      const match = scriptContents.match(lib.regex);
      if (match && match[1]) {
        vulnerabilities.push({
          name: 'Vulnerable Library Detected',
          description: `The page is using ${lib.name} version ${match[1]}, which has known security vulnerabilities. Update to a newer version.`,
          severity: 'Medium',
          location: `${lib.name} ${match[1]}`
        });
      }
    }
  });
}

// Check for potentially sensitive information in HTML
function checkSensitiveInfo(vulnerabilities) {
  const html = document.documentElement.innerHTML;
  
  // Check for potential API keys
  const apiKeyRegex = /["']?api[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9]{16,})["']/gi;
  let match;
  while ((match = apiKeyRegex.exec(html)) !== null) {
    vulnerabilities.push({
      name: 'Exposed API Key',
      description: 'Potential API key found in the page source. API keys should not be exposed in client-side code.',
      severity: 'High',
      location: `API key: ${match[1].substring(0, 4)}...${match[1].substring(match[1].length - 4)}`
    });
  }
} 