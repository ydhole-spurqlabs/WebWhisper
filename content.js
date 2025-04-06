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

// Main scan function - update to include additional vulnerability types
function scanForVulnerabilities(isBackground = false) {
  const vulnerabilities = [];
  
  // For background scans, we might want to limit the scan scope
  // to reduce performance impact on the user's browsing experience
  
  // Check for insecure form submission
  checkInsecureForms(vulnerabilities);
  
  // Check for mixed content
  checkMixedContent(vulnerabilities);
  
  // Check for XSS vulnerabilities
  checkForXSSVulnerabilities(vulnerabilities);
  
  // Check for security header issues
  checkSecurityHeaders(vulnerabilities);
  
  // Check for insecure CORS configurations
  checkCORSConfiguration(vulnerabilities);
  
  // Check for CSP issues
  checkContentSecurityPolicy(vulnerabilities);
  
  // Check for client-side data exposure
  checkClientSideDataExposure(vulnerabilities);
  
  // Check for JavaScript-specific vulnerabilities like prototype pollution
  checkJavaScriptVulnerabilities(vulnerabilities);
  
  // Check for authentication token handling issues
  checkAuthTokenHandling(vulnerabilities);
  
  // Check for unsafe event listener implementations
  checkUnsafeEventListeners(vulnerabilities);
  
  // Check for improper input validation
  checkImproperInputValidation(vulnerabilities);
  
  // Check for DOM manipulation risks
  checkDOMManipulationRisks(vulnerabilities);
  
  // Check for network-related vulnerabilities
  checkNetworkVulnerabilities(vulnerabilities);
  
  // Check for API security issues
  checkAPISecurityIssues(vulnerabilities);
  
  // Check for unvalidated API endpoints
  checkUnvalidatedAPIEndpoints(vulnerabilities);
  
  // Check for improper authentication checks
  checkImproperAuthenticationChecks(vulnerabilities);
  
  // Check for insecure direct object references
  checkInsecureDirectObjectReferences(vulnerabilities);
  
  // Check for rate limiting bypass attempts
  checkRateLimitingBypass(vulnerabilities);
  
  // Check for Cross-Site Request Forgery vulnerabilities
  checkCSRFVulnerabilities(vulnerabilities);
  
  // Check for weak CSRF token implementation
  checkWeakCSRFTokens(vulnerabilities);
  
  // Check for improper request validation
  checkImproperRequestValidation(vulnerabilities);
  
  // Deep scan of JavaScript source code for security patterns
  scanJavaScriptSourceCode(vulnerabilities);
  
  // Only perform these more intensive checks if not in background mode
  // or randomly in background mode to avoid impacting browsing experience
  if (!isBackground || Math.random() < 0.3) {
    // Check for vulnerable libraries
    checkVulnerableLibraries(vulnerabilities);

    // Check for sensitive information in HTML
    checkSensitiveInfo(vulnerabilities);
    
    // Check for unencrypted client-side data
    checkUnencryptedData(vulnerabilities);
  }
  
  // Return found vulnerabilities
  return vulnerabilities;
}

// Check for Cross-Site Scripting (XSS) vulnerabilities
function checkForXSSVulnerabilities(vulnerabilities) {
  // Examine DOM for reflected XSS vulnerabilities
  checkReflectedXSS(vulnerabilities);
  
  // Check for DOM-based XSS vulnerabilities
  checkDOMBasedXSS(vulnerabilities);
  
  // Check for potential stored XSS vulnerabilities
  checkStoredXSS(vulnerabilities);
  
  // Check for inadequate input sanitization
  checkInputSanitization(vulnerabilities);
  
  // Check for unsafe JavaScript injection points
  checkUnsafeJSInjection(vulnerabilities);
  
  // Check for dynamic content rendering issues
  checkDynamicContentRendering(vulnerabilities);
}

// Check for Reflected XSS vulnerabilities
function checkReflectedXSS(vulnerabilities) {
  // Get URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  
  // Check if URL parameters are reflected in the page without sanitization
  for (const [key, value] of urlParams.entries()) {
    // Skip empty parameters
    if (!value.trim()) continue;
    
    // XSS test strings that might indicate vulnerability if found in HTML
    const xssTestStrings = [
      `<script>`, `</script>`,
      `<img`, `onerror=`,
      `javascript:`,
      `onload=`, `onclick=`,
      `%3Cscript%3E`, // URL encoded <script>
      `alert(`, `eval(`
    ];
    
    // Check if any parameter value contains potential XSS payloads
    const containsXssPayload = xssTestStrings.some(str => value.toLowerCase().includes(str.toLowerCase()));
    
    if (containsXssPayload) {
      // If URL contains potential XSS payload, check if it's reflected in the page
      const htmlContent = document.documentElement.innerHTML;
      
      if (htmlContent.includes(value)) {
        vulnerabilities.push({
          name: 'Potential Reflected XSS',
          description: `URL parameter "${key}" containing potential XSS payload is reflected in the page without proper sanitization.`,
          severity: 'High',
          location: `URL parameter: ${key}=${value}`
        });
      }
    } else {
      // Even if URL doesn't contain obvious XSS payloads, check if parameters are reflected without encoding
      const htmlContent = document.documentElement.innerHTML;
      
      // Check if parameter value appears unencoded in HTML
      if (htmlContent.includes(value)) {
        // Search for the value in text nodes or attribute values
        const textNodes = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        let node;
        let foundInSafeContext = false;
        
        // Check if value is found only in safe contexts
        while (node = textNodes.nextNode()) {
          if (node.nodeValue.includes(value)) {
            // If parent is a script tag, it could be vulnerable
            if (node.parentElement.tagName === 'SCRIPT') {
              vulnerabilities.push({
                name: 'Potential Reflected XSS in Script',
                description: `URL parameter "${key}" is reflected directly within a script tag without sanitization.`,
                severity: 'High',
                location: `URL parameter reflected in script: ${key}=${value}`
              });
            } else {
              foundInSafeContext = true;
            }
          }
        }
        
        // Check if value is found in dangerous attributes
        const allElements = document.querySelectorAll('*');
        for (const element of allElements) {
          const attributes = element.attributes;
          for (let i = 0; i < attributes.length; i++) {
            const attr = attributes[i];
            if (attr.value.includes(value)) {
              // Check if attribute is a dangerous event handler
              if (attr.name.startsWith('on') || attr.name === 'href' && attr.value.startsWith('javascript:')) {
                vulnerabilities.push({
                  name: 'Reflected XSS in Event Handler',
                  description: `URL parameter "${key}" is reflected in a JavaScript event handler attribute without sanitization.`,
                  severity: 'High',
                  location: `URL parameter reflected in ${element.tagName} ${attr.name} attribute: ${key}=${value}`
                });
              }
            }
          }
        }
      }
    }
  }
}

// Check for DOM-based XSS vulnerabilities
function checkDOMBasedXSS(vulnerabilities) {
  // Get JavaScript code from all script tags
  const scripts = document.querySelectorAll('script');
  let scriptContent = '';
  
  for (const script of scripts) {
    if (!script.src && script.textContent) {
      scriptContent += script.textContent + '\n';
    }
  }
  
  // Check for common DOM XSS sink patterns
  const domXssSinkPatterns = [
    { pattern: /document\.write\s*\(/g, name: 'document.write()' },
    { pattern: /\.innerHTML\s*=/g, name: 'innerHTML assignment' },
    { pattern: /\.outerHTML\s*=/g, name: 'outerHTML assignment' },
    { pattern: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML()' },
    { pattern: /eval\s*\(/g, name: 'eval()' },
    { pattern: /setTimeout\s*\(\s*['"`]/g, name: 'setTimeout with string argument' },
    { pattern: /setInterval\s*\(\s*['"`]/g, name: 'setInterval with string argument' },
    { pattern: /new\s+Function\s*\(/g, name: 'new Function()' }
  ];
  
  // Check for source -> sink flows
  const sourcePatterns = [
    { pattern: /location\.search/g, name: 'location.search' },
    { pattern: /location\.hash/g, name: 'location.hash' },
    { pattern: /location\.href/g, name: 'location.href' },
    { pattern: /document\.referrer/g, name: 'document.referrer' },
    { pattern: /document\.URL/g, name: 'document.URL' },
    { pattern: /document\.documentURI/g, name: 'document.documentURI' },
    { pattern: /window\.name/g, name: 'window.name' }
  ];
  
  // Check for direct flows from sources to sinks
  for (const source of sourcePatterns) {
    if (source.pattern.test(scriptContent)) {
      for (const sink of domXssSinkPatterns) {
        if (sink.pattern.test(scriptContent)) {
          // Analyze potential flow from source to sink
          // This is a simplified check - a real scanner would track data flow
          vulnerabilities.push({
            name: 'Potential DOM-based XSS',
            description: `Code uses ${source.name} (user-controllable input) and ${sink.name} (dangerous DOM manipulation), which could lead to DOM-based XSS.`,
            severity: 'High',
            location: `Script using ${source.name} and ${sink.name}`
          });
          break; // Just report one vulnerability per source
        }
      }
    }
  }
  
  // Check for dangerous uses of jQuery (if jQuery is detected)
  if (typeof window.jQuery !== 'undefined' || scriptContent.includes('jQuery') || scriptContent.includes('$(' )) {
    const jQuerySinks = [
      { pattern: /\$\(\s*.*\s*\)\.html\s*\(/g, name: '$.html()' },
      { pattern: /\$\.\s*parseHTML\s*\(/g, name: '$.parseHTML()' },
      { pattern: /\$\(\s*[^{].*\s*\)/g, name: '$(...)' }, // jQuery selector with potential HTML
    ];
    
    for (const sink of jQuerySinks) {
      if (sink.pattern.test(scriptContent)) {
        for (const source of sourcePatterns) {
          if (source.pattern.test(scriptContent)) {
            vulnerabilities.push({
              name: 'Potential jQuery DOM-based XSS',
              description: `Code appears to use ${source.name} (user input) with ${sink.name}, which may lead to DOM-based XSS if not properly sanitized.`,
              severity: 'Medium',
              location: `jQuery using ${source.name} with ${sink.name}`
            });
            break;
          }
        }
      }
    }
  }
}

// Check for potential stored XSS vulnerabilities
function checkStoredXSS(vulnerabilities) {
  // Check for content that looks like it could be user-generated
  // This is a heuristic approach as we can't know for sure what's user-generated
  const potentialUserContentContainers = [
    ...document.querySelectorAll('div.comment, div.user-content, div.post, article, .review, .user-generated'),
    ...document.querySelectorAll('[data-user-content], [data-author]')
  ];
  
  for (const container of potentialUserContentContainers) {
    // Check for signs of insufficient HTML encoding
    const htmlContent = container.innerHTML;
    
    // Look for potentially unescaped HTML special characters in what appears to be user content
    if (/<[a-z]+(\s+[a-z]+\s*=\s*['"][^'"]*['"])*\s*>/i.test(htmlContent)) {
      // Found something that looks like an HTML tag in what might be user content
      
      // Try to determine if this is actually dangerous
      // Skip if it looks like a common benign tag
      const benignTags = ['div', 'span', 'p', 'br', 'strong', 'em', 'i', 'b', 'a'];
      let isBenign = true;
      
      // Check if there are script tags or event handlers
      if (/<script/i.test(htmlContent) || 
          /on\w+\s*=/i.test(htmlContent) || 
          /javascript:/i.test(htmlContent)) {
        isBenign = false;
      }
      
      // Check for other potentially dangerous tags
      if (/<(iframe|object|embed|form|input|button|svg)/i.test(htmlContent)) {
        isBenign = false;
      }
      
      if (!isBenign) {
        vulnerabilities.push({
          name: 'Potential Stored XSS',
          description: 'User-generated content appears to contain unsanitized HTML, which could allow stored XSS attacks.',
          severity: 'High',
          location: `Element: ${container.tagName.toLowerCase()}${container.id ? '#' + container.id : ''}`
        });
      }
    }
  }
}

// Check for inadequate input sanitization
function checkInputSanitization(vulnerabilities) {
  // Check all forms to see if they handle input safely
  const forms = document.querySelectorAll('form');
  
  for (const form of forms) {
    // Check if the form has any client-side validation
    const hasValidation = form.getAttribute('novalidate') !== 'true';
    const formInputs = form.querySelectorAll('input, textarea');
    let hasInputValidation = false;
    
    for (const input of formInputs) {
      if (input.getAttribute('pattern') || 
          input.hasAttribute('required') || 
          input.getAttribute('type') === 'email' || 
          input.getAttribute('type') === 'number' ||
          input.getAttribute('maxlength')) {
        hasInputValidation = true;
        break;
      }
    }
    
    // Look for form handlers
    const formHandler = form.getAttribute('onsubmit');
    const htmlContent = document.documentElement.innerHTML;
    
    // Look for submission handler that might validate input
    // This is an imperfect heuristic
    let hasFormSubmitValidation = false;
    if (formHandler && formHandler.includes('valid')) {
      hasFormSubmitValidation = true;
    }
    
    // Check for form ID in script tags
    const formId = form.getAttribute('id');
    if (formId) {
      const scripts = document.querySelectorAll('script');
      for (const script of scripts) {
        if (script.textContent.includes(formId) && 
            (script.textContent.includes('validate') || script.textContent.includes('sanitize'))) {
          hasFormSubmitValidation = true;
          break;
        }
      }
    }
    
    // If no validation is found and there are text inputs, flag it
    const hasTextInputs = [...formInputs].some(input => 
      input.type === 'text' || input.type === 'textarea' || input.type === 'search' || input.type === 'url');
    
    if (hasTextInputs && !hasValidation && !hasInputValidation && !hasFormSubmitValidation) {
      vulnerabilities.push({
        name: 'Inadequate Input Sanitization',
        description: 'Form accepts text input without apparent client-side validation or sanitization, which could lead to XSS vulnerabilities if server-side validation is also insufficient.',
        severity: 'Medium',
        location: `Form: ${formId ? '#' + formId : form.action || 'Unknown form'}`
      });
    }
  }
}

// Check for unsafe JavaScript injection points
function checkUnsafeJSInjection(vulnerabilities) {
  // Examine inline event handlers for potential unsafe patterns
  const allElements = document.querySelectorAll('*');
  
  for (const element of allElements) {
    // Check each attribute for inline event handlers
    for (let i = 0; i < element.attributes.length; i++) {
      const attr = element.attributes[i];
      
      // Check if it's an event handler attribute
      if (attr.name.startsWith('on')) {
        // Check for dynamic content in the handler that might be unsanitized
        const value = attr.value;
        
        // Check for patterns that suggest interpolation of unsanitized values
        if (value.includes('this.value') || 
            value.includes('value.') || 
            value.includes('input.value') || 
            value.includes('target.value') || 
            value.includes('value +') ||
            value.includes('+ value')) {
          
          vulnerabilities.push({
            name: 'Unsafe JavaScript Event Handler',
            description: 'Event handler appears to directly use input values without sanitization, which could enable XSS attacks.',
            severity: 'Medium',
            location: `${element.tagName.toLowerCase()} element with ${attr.name}="${attr.value}"`
          });
        }
      }
    }
  }
  
  // Check scripts for document.write with variable content
  const scripts = document.querySelectorAll('script');
  for (const script of scripts) {
    if (!script.src) {
      const content = script.textContent;
      
      // Check for potentially unsafe patterns
      if ((content.includes('document.write') && content.includes('var ')) ||
          (content.includes('innerHTML') && content.includes('var ')) ||
          (content.includes('outerHTML') && content.includes('var '))) {
        
        vulnerabilities.push({
          name: 'Potentially Unsafe Dynamic HTML Injection',
          description: 'JavaScript code appears to modify the DOM with dynamically generated content, which could lead to XSS if input is not properly sanitized.',
          severity: 'Medium',
          location: 'Inline script'
        });
      }
    }
  }
}

// Check for dynamic content rendering issues
function checkDynamicContentRendering(vulnerabilities) {
  // Check for frameworks known to have secure rendering by default
  const usingReact = typeof window.React !== 'undefined' || document.querySelector('[data-reactroot]');
  const usingVue = typeof window.Vue !== 'undefined' || document.querySelector('[data-v-]');
  const usingAngular = typeof window.angular !== 'undefined' || document.querySelector('[ng-]');
  
  // Heuristic check for template literals in scripts
  const scripts = document.querySelectorAll('script');
  let potentiallyUnsafeTemplating = false;
  
  for (const script of scripts) {
    if (!script.src) {
      const content = script.textContent;
      
      // Look for template literal usage
      if (content.includes('`') && content.includes('${')) {
        // Check if template contents are being directly inserted into the DOM
        if (content.includes('innerHTML') || 
            content.includes('outerHTML') || 
            content.includes('document.write') ||
            content.includes('insertAdjacentHTML')) {
          
          potentiallyUnsafeTemplating = true;
          break;
        }
      }
    }
  }
  
  // Check for custom template engines
  const hasHandlebars = typeof window.Handlebars !== 'undefined';
  const hasMustache = typeof window.Mustache !== 'undefined';
  const hasUnderscore = typeof window._ !== 'undefined' && typeof window._.template === 'function';
  
  // If using custom templating without a secure framework, warn about potential issues
  if (potentiallyUnsafeTemplating && !usingReact && !usingVue && !usingAngular) {
    vulnerabilities.push({
      name: 'Potentially Unsafe Dynamic Content Rendering',
      description: 'Page appears to use custom templating to dynamically render content. Ensure proper output encoding is applied to prevent XSS vulnerabilities.',
      severity: 'Medium',
      location: 'Dynamic content rendering'
    });
  }
  
  // If using template libraries known to not escape by default, warn about it
  if ((hasHandlebars || hasMustache || hasUnderscore) && potentiallyUnsafeTemplating) {
    const engine = hasHandlebars ? 'Handlebars' : hasMustache ? 'Mustache' : 'Underscore';
    
    vulnerabilities.push({
      name: 'Template Engine Without Automatic Escaping',
      description: `Page uses ${engine} for templating. Ensure proper escaping is applied to all variables to prevent XSS vulnerabilities.`,
      severity: 'Medium',
      location: `${engine} template engine`
    });
  }
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

// Check for security header issues
function checkSecurityHeaders(vulnerabilities) {
  // We can't directly access response headers using content scripts
  // But we can use a trick to get some security headers via meta tags or JavaScript
  
  // Check for X-Frame-Options via CSP frame-ancestors or meta tags
  checkXFrameOptions(vulnerabilities);
  
  // Check for X-XSS-Protection via meta tags
  checkXXSSProtection(vulnerabilities);
  
  // Check for Referrer-Policy
  checkReferrerPolicy(vulnerabilities);
  
  // Check for other important security headers that might be reflected in meta tags
  checkOtherSecurityHeaders(vulnerabilities);
}

// Check for X-Frame-Options header issues
function checkXFrameOptions(vulnerabilities) {
  // Check for meta tag equivalent
  const metaTags = document.querySelectorAll('meta[http-equiv="X-Frame-Options"]');
  
  if (metaTags.length === 0) {
    // Check if CSP has frame-ancestors directive which can replace X-Frame-Options
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const cspHeader = cspMeta ? cspMeta.getAttribute('content') : null;
    
    if (!cspHeader || !cspHeader.includes('frame-ancestors')) {
      vulnerabilities.push({
        name: 'Missing X-Frame-Options Header',
        description: 'The page does not appear to set X-Frame-Options header or equivalent CSP directive, which helps prevent clickjacking attacks.',
        severity: 'Medium',
        location: 'HTTP Headers'
      });
    }
  } else {
    // Check if the value is secure
    const value = metaTags[0].getAttribute('content');
    if (value && (value.toLowerCase() !== 'deny' && value.toLowerCase() !== 'sameorigin')) {
      vulnerabilities.push({
        name: 'Weak X-Frame-Options Configuration',
        description: `X-Frame-Options is set to "${value}" which may not provide sufficient protection against clickjacking. Recommended values are "DENY" or "SAMEORIGIN".`,
        severity: 'Low',
        location: 'X-Frame-Options Meta Tag'
      });
    }
  }
}

// Check for X-XSS-Protection header issues
function checkXXSSProtection(vulnerabilities) {
  // Check for meta tag equivalent
  const metaTags = document.querySelectorAll('meta[http-equiv="X-XSS-Protection"]');
  
  if (metaTags.length === 0) {
    // While modern browsers phase this out in favor of CSP, it's still a good defense in depth measure
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    
    // Only report if CSP is also missing or weak
    if (!cspMeta || isWeakCSP(cspMeta.getAttribute('content'))) {
      vulnerabilities.push({
        name: 'Missing X-XSS-Protection Header',
        description: 'The page does not set X-XSS-Protection header. While modern browsers rely more on CSP, this header provides additional protection for older browsers.',
        severity: 'Low',
        location: 'HTTP Headers'
      });
    }
  } else {
    // Check if the value is secure
    const value = metaTags[0].getAttribute('content');
    if (value && value !== '1; mode=block') {
      vulnerabilities.push({
        name: 'Weak X-XSS-Protection Configuration',
        description: `X-XSS-Protection is set to "${value}" which may not provide optimal protection. Recommended value is "1; mode=block".`,
        severity: 'Low',
        location: 'X-XSS-Protection Meta Tag'
      });
    }
  }
}

// Check for Referrer-Policy header issues
function checkReferrerPolicy(vulnerabilities) {
  // Check for meta tag referrer
  const metaTags = document.querySelectorAll('meta[name="referrer"]');
  const referrerPolicy = document.referrerPolicy; // Get the document's referrer policy
  
  if (metaTags.length === 0 && referrerPolicy === '' || referrerPolicy === 'no-referrer-when-downgrade') {
    vulnerabilities.push({
      name: 'Missing or Weak Referrer-Policy',
      description: 'The page does not set a strict Referrer-Policy. This could lead to leaking sensitive information in the Referer header when navigating to external sites.',
      severity: 'Low',
      location: 'HTTP Headers'
    });
  } else if (metaTags.length > 0) {
    // Check specific meta tag value
    const value = metaTags[0].getAttribute('content');
    if (value && (value === 'unsafe-url' || value === 'origin-when-cross-origin' || value === '')) {
      vulnerabilities.push({
        name: 'Weak Referrer-Policy Configuration',
        description: `Referrer-Policy is set to "${value}" which may leak sensitive information in URLs. Consider using stricter values like "no-referrer" or "same-origin".`,
        severity: 'Low',
        location: 'Referrer-Policy Meta Tag'
      });
    }
  }
}

// Check for other important security headers
function checkOtherSecurityHeaders(vulnerabilities) {
  // Check for Strict-Transport-Security
  const hstsMetaTag = document.querySelector('meta[http-equiv="Strict-Transport-Security"]');
  
  if (!hstsMetaTag && window.location.protocol === 'https:') {
    vulnerabilities.push({
      name: 'Missing Strict-Transport-Security Header',
      description: 'The page does not appear to set the HTTP Strict-Transport-Security header, which helps ensure connections to the site are always via HTTPS.',
      severity: 'Medium',
      location: 'HTTP Headers'
    });
  }
  
  // Check for Feature-Policy/Permissions-Policy
  const featurePolicyMeta = document.querySelector('meta[http-equiv="Feature-Policy"], meta[http-equiv="Permissions-Policy"]');
  
  if (!featurePolicyMeta) {
    vulnerabilities.push({
      name: 'Missing Permissions-Policy Header',
      description: 'The page does not appear to set the Permissions-Policy header, which helps control which browser features and APIs can be used on the page.',
      severity: 'Low',
      location: 'HTTP Headers'
    });
  }
}

// Helper function to determine if a CSP is weak
function isWeakCSP(cspContent) {
  if (!cspContent) return true;
  
  // CSP is weak if it includes 'unsafe-inline', 'unsafe-eval' or uses wildcards '*'
  return cspContent.includes('unsafe-inline') || 
         cspContent.includes('unsafe-eval') || 
         cspContent.includes("default-src *") ||
         cspContent.includes("script-src *");
}

// Check for insecure CORS configurations
function checkCORSConfiguration(vulnerabilities) {
  // We can't directly check CORS headers from content scripts
  // But we can look for signs of insecure CORS patterns in JavaScript
  
  // Get all script contents
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for typical patterns that might indicate insecure CORS configurations
  
  // 1. Check for AJAX requests with inappropriate withCredentials settings
  if (scriptContent.includes('withCredentials: true') && 
      scriptContent.match(/crossorigin|cors|Access-Control-Allow-Origin/i)) {
    
    vulnerabilities.push({
      name: 'Potential Insecure CORS Configuration',
      description: 'Code appears to make cross-origin requests with credentials. If the server uses a wildcard in Access-Control-Allow-Origin, this could lead to security vulnerabilities.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // 2. Check for JSONP usage, which can bypass CORS restrictions but has security implications
  if (scriptContent.match(/jsonp|callback=/i) && 
      scriptContent.match(/appendChild\s*\(\s*script\s*\)|createElement\s*\(\s*['"]script['"]/) ) {
    
    vulnerabilities.push({
      name: 'JSONP Usage Detected',
      description: 'The page appears to use JSONP for cross-origin requests. JSONP can bypass CORS restrictions but may introduce security risks if the external API is not trusted.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // 3. Look for signs of CORS proxy usage or bypassing
  if (scriptContent.match(/cors-anywhere|cors proxy|proxy\.php|corsproxy/i)) {
    vulnerabilities.push({
      name: 'CORS Proxy Usage',
      description: 'The page appears to use a CORS proxy to bypass Same-Origin Policy restrictions. This may introduce security risks if not properly implemented.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // 4. Check for postMessage usage without proper origin checking
  if (scriptContent.includes('postMessage(') && 
      !scriptContent.match(/\.origin\s*===|\.origin\s*==|targetOrigin/i)) {
    
    vulnerabilities.push({
      name: 'Insecure Cross-Origin Communication',
      description: 'The page uses postMessage() for cross-origin communication without apparent origin validation, which could allow malicious sites to send messages to this page.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // 5. Check crossorigin attributes on scripts, images, etc.
  const crossOriginElements = document.querySelectorAll('[crossorigin]');
  
  for (const element of crossOriginElements) {
    const crossoriginValue = element.getAttribute('crossorigin');
    
    // anonymous is safer than use-credentials in many contexts
    if (crossoriginValue === 'use-credentials') {
      vulnerabilities.push({
        name: 'Cross-Origin Resource using Credentials',
        description: `A ${element.tagName.toLowerCase()} element is using crossorigin="use-credentials", which sends cookies and authentication with requests. Ensure the server properly restricts Access-Control-Allow-Origin.`,
        severity: 'Low',
        location: `${element.tagName.toLowerCase()} element with src="${element.getAttribute('src')}"`
      });
    }
  }
}

// Check for CSP issues
function checkContentSecurityPolicy(vulnerabilities) {
  // Check for CSP via meta tag
  const cspMetaTag = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  let cspContent = null;
  
  if (cspMetaTag) {
    cspContent = cspMetaTag.getAttribute('content');
  }
  
  // If no CSP is found via meta tag, report it (we can't check HTTP headers directly)
  if (!cspContent) {
    vulnerabilities.push({
      name: 'Missing Content Security Policy',
      description: 'No Content Security Policy meta tag was found. CSP helps prevent XSS attacks by restricting the sources from which content can be loaded.',
      severity: 'Medium',
      location: 'HTTP Headers/Meta Tags'
    });
    return;
  }
  
  // CSP exists, check for weak configurations
  
  // Check for unsafe-inline in script-src or default-src
  if (cspContent.match(/script-src[^;]*'unsafe-inline'/i) || 
      (cspContent.includes('default-src') && cspContent.match(/default-src[^;]*'unsafe-inline'/i) && !cspContent.includes('script-src'))) {
    
    vulnerabilities.push({
      name: 'Weak Content Security Policy: unsafe-inline',
      description: 'The Content Security Policy allows unsafe-inline scripts, which negates much of the XSS protection that CSP provides.',
      severity: 'Medium',
      location: 'Content-Security-Policy'
    });
  }
  
  // Check for unsafe-eval
  if (cspContent.match(/script-src[^;]*'unsafe-eval'/i) || 
      (cspContent.includes('default-src') && cspContent.match(/default-src[^;]*'unsafe-eval'/i) && !cspContent.includes('script-src'))) {
    
    vulnerabilities.push({
      name: 'Weak Content Security Policy: unsafe-eval',
      description: 'The Content Security Policy allows unsafe-eval, which permits the use of eval() and similar functions that can introduce XSS vulnerabilities.',
      severity: 'Medium',
      location: 'Content-Security-Policy'
    });
  }
  
  // Check for wildcards in script-src or default-src
  if (cspContent.match(/script-src[^;]*\*/i) || 
      (cspContent.includes('default-src') && cspContent.match(/default-src[^;]*\*/i) && !cspContent.includes('script-src'))) {
    
    vulnerabilities.push({
      name: 'Weak Content Security Policy: Wildcard Source',
      description: 'The Content Security Policy includes a wildcard (*) in script sources, which allows scripts from any origin and reduces the effectiveness of CSP.',
      severity: 'Medium',
      location: 'Content-Security-Policy'
    });
  }
  
  // Check if report-uri/report-to is configured
  if (!cspContent.includes('report-uri') && !cspContent.includes('report-to')) {
    vulnerabilities.push({
      name: 'CSP Reporting Not Configured',
      description: 'The Content Security Policy does not include a reporting mechanism (report-uri or report-to directive). Reporting helps identify and fix CSP violations.',
      severity: 'Low',
      location: 'Content-Security-Policy'
    });
  }
  
  // Check for missing frame-ancestors
  if (!cspContent.includes('frame-ancestors')) {
    vulnerabilities.push({
      name: 'CSP Missing frame-ancestors Directive',
      description: 'The Content Security Policy does not specify frame-ancestors directive, which helps prevent clickjacking attacks.',
      severity: 'Low',
      location: 'Content-Security-Policy'
    });
  }
  
  // Check for missing object-src
  if (!cspContent.includes('object-src')) {
    vulnerabilities.push({
      name: 'CSP Missing object-src Directive',
      description: 'The Content Security Policy does not specify object-src directive, which helps prevent embedding of potentially malicious Flash or other plugin content.',
      severity: 'Low',
      location: 'Content-Security-Policy'
    });
  }
  
  // Check for nonce or strict-dynamic usage 
  // (modern and more secure approach compared to unsafe-inline)
  const hasNonce = cspContent.includes('nonce-');
  const hasStrictDynamic = cspContent.includes('strict-dynamic');
  
  if (!hasNonce && !hasStrictDynamic && cspContent.includes('unsafe-inline')) {
    vulnerabilities.push({
      name: 'CSP Uses Legacy Approach',
      description: 'The Content Security Policy uses unsafe-inline without nonces or strict-dynamic. Consider upgrading to a nonce-based approach for better security.',
      severity: 'Low',
      location: 'Content-Security-Policy'
    });
  }
}

// Check for client-side data exposure issues
function checkClientSideDataExposure(vulnerabilities) {
  // Check localStorage for sensitive data
  checkLocalStorage(vulnerabilities);
  
  // Check sessionStorage for sensitive data
  checkSessionStorage(vulnerabilities);
  
  // Check for sensitive data in cookies
  checkCookies(vulnerabilities);
  
  // Check JavaScript variables and objects for sensitive data
  checkJavaScriptObjects(vulnerabilities);
  
  // Check input fields with sensitive information
  checkSensitiveInputs(vulnerabilities);
  
  // Check for sensitive data in data attributes
  checkDataAttributes(vulnerabilities);
  
  // Check for exposed API keys
  checkExposedAPIKeys(vulnerabilities);
}

// Check localStorage for potentially sensitive data
function checkLocalStorage(vulnerabilities) {
  try {
    if (window.localStorage) {
      // Patterns that might indicate sensitive information
      const sensitivePatterns = [
        { pattern: /password|passwd|pwd|secret/i, type: 'Password' },
        { pattern: /token|jwt|auth|api.?key/i, type: 'Authentication Token' },
        { pattern: /credit|card|cvv|cvc|ccv|cc.?num|cardnum/i, type: 'Credit Card' },
        { pattern: /ssn|social.?security/i, type: 'Social Security Number' },
        { pattern: /account|routing|bank/i, type: 'Financial Information' },
        { pattern: /address|email|phone|mobile|zip|postal/i, type: 'Personal Information' }
      ];
      
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        
        // Skip localStorage items that are clearly not sensitive
        if (key.includes('preference') || 
            key.includes('theme') || 
            key.includes('language') || 
            key.includes('ui_') || 
            key.includes('lastVisited')) {
          continue;
        }
        
        // Check if key or value matches sensitive patterns
        for (const pattern of sensitivePatterns) {
          if (pattern.pattern.test(key) || (value && typeof value === 'string' && pattern.pattern.test(value))) {
            vulnerabilities.push({
              name: 'Potential Sensitive Data Exposure in localStorage',
              description: `Potential ${pattern.type} information stored in client-side localStorage under key "${key}". Sensitive data should not be stored unencrypted in localStorage.`,
              severity: 'High',
              location: `localStorage["${key}"]`
            });
            break;
          }
        }
        
        // Check for what looks like JWT tokens
        if (value && typeof value === 'string' && 
            /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(value)) {
          vulnerabilities.push({
            name: 'JWT Token Stored in localStorage',
            description: 'A JWT token appears to be stored in localStorage. If this contains sensitive claims, it could be vulnerable to theft via XSS attacks.',
            severity: 'Medium',
            location: `localStorage["${key}"]`
          });
        }
      }
    }
  } catch (e) {
    // localStorage might be disabled or restricted, which is expected in some cases
    console.log('Error checking localStorage:', e);
  }
}

// Check sessionStorage for potentially sensitive data
function checkSessionStorage(vulnerabilities) {
  try {
    if (window.sessionStorage) {
      // Patterns that might indicate sensitive information
      const sensitivePatterns = [
        { pattern: /password|passwd|pwd|secret/i, type: 'Password' },
        { pattern: /token|jwt|auth|api.?key/i, type: 'Authentication Token' },
        { pattern: /credit|card|cvv|cvc|ccv|cc.?num|cardnum/i, type: 'Credit Card' },
        { pattern: /ssn|social.?security/i, type: 'Social Security Number' },
        { pattern: /account|routing|bank/i, type: 'Financial Information' },
        { pattern: /address|email|phone|mobile|zip|postal/i, type: 'Personal Information' }
      ];
      
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        
        // Skip sessionStorage items that are clearly not sensitive
        if (key.includes('preference') || 
            key.includes('theme') || 
            key.includes('language') || 
            key.includes('ui_') || 
            key.includes('lastVisited')) {
          continue;
        }
        
        // Check if key or value matches sensitive patterns
        for (const pattern of sensitivePatterns) {
          if (pattern.pattern.test(key) || (value && typeof value === 'string' && pattern.pattern.test(value))) {
            vulnerabilities.push({
              name: 'Potential Sensitive Data Exposure in sessionStorage',
              description: `Potential ${pattern.type} information stored in client-side sessionStorage under key "${key}". While sessionStorage is cleared when the session ends, it's still vulnerable to XSS attacks.`,
              severity: 'Medium',
              location: `sessionStorage["${key}"]`
            });
            break;
          }
        }
        
        // Check for what looks like JWT tokens
        if (value && typeof value === 'string' && 
            /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(value)) {
          vulnerabilities.push({
            name: 'JWT Token Stored in sessionStorage',
            description: 'A JWT token appears to be stored in sessionStorage. If this contains sensitive claims, it could be vulnerable to theft via XSS attacks.',
            severity: 'Medium',
            location: `sessionStorage["${key}"]`
          });
        }
      }
    }
  } catch (e) {
    // sessionStorage might be disabled or restricted, which is expected in some cases
    console.log('Error checking sessionStorage:', e);
  }
}

// Check cookies for potentially sensitive data
function checkCookies(vulnerabilities) {
  try {
    const cookies = document.cookie.split(';');
    
    // Patterns that might indicate sensitive information
    const sensitivePatterns = [
      { pattern: /password|passwd|pwd|secret/i, type: 'Password' },
      { pattern: /token|jwt|auth|api.?key/i, type: 'Authentication Token' },
      { pattern: /credit|card|cvv|cvc|ccv|cc.?num|cardnum/i, type: 'Credit Card' },
      { pattern: /ssn|social.?security/i, type: 'Social Security Number' },
      { pattern: /account|routing|bank/i, type: 'Financial Information' },
      { pattern: /address|email|phone|mobile|zip|postal/i, type: 'Personal Information' }
    ];
    
    for (const cookie of cookies) {
      if (!cookie.trim()) continue;
      
      const [key, value] = cookie.split('=').map(part => part.trim());
      
      // Skip obvious non-sensitive cookies
      if (key.includes('_ga') || 
          key.includes('_gid') || 
          key.includes('visitor') || 
          key.includes('PHPSESSID') || 
          key.includes('_utm')) {
        continue;
      }
      
      // Check for sensitive data in cookie names or values
      for (const pattern of sensitivePatterns) {
        if (pattern.pattern.test(key) || (value && pattern.pattern.test(decodeURIComponent(value)))) {
          // Check if cookie is secure and httpOnly
          const isSecure = cookie.toLowerCase().includes('secure');
          const isHttpOnly = cookie.toLowerCase().includes('httponly');
          
          if (!isSecure || !isHttpOnly) {
            vulnerabilities.push({
              name: 'Insecure Cookie with Sensitive Data',
              description: `Cookie "${key}" appears to contain ${pattern.type} information but is missing ${!isSecure ? 'Secure' : ''}${!isSecure && !isHttpOnly ? ' and ' : ''}${!isHttpOnly ? 'HttpOnly' : ''} flag(s).`,
              severity: 'High',
              location: `Cookie: ${key}`
            });
          }
          break;
        }
      }
      
      // Check for JWT tokens
      if (value && /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(decodeURIComponent(value))) {
        // Check if cookie is secure and httpOnly
        const isSecure = cookie.toLowerCase().includes('secure');
        const isHttpOnly = cookie.toLowerCase().includes('httponly');
        
        if (!isSecure || !isHttpOnly) {
          vulnerabilities.push({
            name: 'JWT Token in Insecure Cookie',
            description: `Cookie "${key}" contains a JWT token but is missing ${!isSecure ? 'Secure' : ''}${!isSecure && !isHttpOnly ? ' and ' : ''}${!isHttpOnly ? 'HttpOnly' : ''} flag(s).`,
            severity: 'High',
            location: `Cookie: ${key}`
          });
        }
      }
    }
  } catch (e) {
    console.log('Error checking cookies:', e);
  }
}

// Check for sensitive data in JavaScript objects
function checkJavaScriptObjects(vulnerabilities) {
  // Get all inline scripts
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Patterns that might indicate sensitive information hardcoded in JavaScript
  const sensitivePatterns = [
    { pattern: /password\s*[:=]\s*['"]((?!this).)[^'"]*['"]/i, type: 'Password' },
    { pattern: /api.?key\s*[:=]\s*['"]([^'"]*)['"]/i, type: 'API Key' },
    { pattern: /secret\s*[:=]\s*['"]([^'"]*)['"]/i, type: 'Secret' },
    { pattern: /token\s*[:=]\s*['"]([^'"]*)['"]/i, type: 'Token' },
    { pattern: /access.?token\s*[:=]\s*['"]([^'"]*)['"]/i, type: 'Access Token' },
    { pattern: /credit.?card\s*[:=]\s*['"]([^'"]*)['"]/i, type: 'Credit Card' }
  ];
  
  // Check each pattern
  for (const pattern of sensitivePatterns) {
    const matches = scriptContent.match(pattern.pattern);
    
    if (matches) {
      vulnerabilities.push({
        name: `${pattern.type} Exposed in JavaScript`,
        description: `A ${pattern.type.toLowerCase()} appears to be hardcoded in JavaScript. Sensitive data should not be included in client-side code.`,
        severity: 'High',
        location: 'JavaScript Code'
      });
    }
  }
  
  // Check for what appears to be personal data
  if (scriptContent.match(/social.?security.?number\s*[:=]\s*['"]([^'"]*)['"]/i) ||
      scriptContent.match(/ssn\s*[:=]\s*['"]([^'"]*)['"]/i)) {
    vulnerabilities.push({
      name: 'Social Security Number Exposed in JavaScript',
      description: 'What appears to be a Social Security Number is hardcoded in JavaScript. This is highly sensitive data that should never be in client-side code.',
      severity: 'Critical',
      location: 'JavaScript Code'
    });
  }
  
  // Look for AWS keys pattern
  if (scriptContent.match(/AKIA[0-9A-Z]{16}/)) {
    vulnerabilities.push({
      name: 'AWS Access Key Exposed',
      description: 'What appears to be an AWS Access Key ID is present in the JavaScript code. Cloud provider credentials should never be exposed in client-side code.',
      severity: 'Critical',
      location: 'JavaScript Code'
    });
  }
}

// Check input fields with potentially sensitive information
function checkSensitiveInputs(vulnerabilities) {
  // Look for sensitive form fields that are not properly protected
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  
  for (const input of passwordInputs) {
    // Check if autocomplete is not disabled for password fields
    if (!input.getAttribute('autocomplete') || input.getAttribute('autocomplete') !== 'off') {
      vulnerabilities.push({
        name: 'Password Field Without Autocomplete Protection',
        description: 'Password field allows browser autocomplete, which may store the password insecurely or fill it automatically in unsafe contexts.',
        severity: 'Low',
        location: `Password field ${input.name ? 'name="' + input.name + '"' : (input.id ? 'id="' + input.id + '"' : '')}`
      });
    }
  }
  
  // Check for credit card fields
  const creditCardInputs = Array.from(document.querySelectorAll('input[type="text"], input[type="tel"], input[type="number"]')).filter(input => {
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    
    return name.includes('card') || name.includes('credit') || name.includes('cc') ||
           id.includes('card') || id.includes('credit') || id.includes('cc') ||
           placeholder.includes('card') || placeholder.includes('credit') || placeholder.includes('cc');
  });
  
  for (const input of creditCardInputs) {
    // Check if credit card form is submitted over HTTPS
    const form = input.closest('form');
    
    if (form) {
      const action = form.getAttribute('action');
      
      if (action && action.startsWith('http:')) {
        vulnerabilities.push({
          name: 'Credit Card Information Submitted Insecurely',
          description: 'A form containing what appears to be credit card information is submitted over unencrypted HTTP. Financial information should always be transmitted using HTTPS.',
          severity: 'Critical',
          location: `Form with action="${action}"`
        });
      }
    }
  }
}

// Check for sensitive data in data attributes
function checkDataAttributes(vulnerabilities) {
  // Get all elements in the document
  const allElements = document.querySelectorAll('*');
  
  // Patterns that might indicate sensitive information
  const sensitivePatterns = [
    { pattern: /password|passwd|pwd|secret/i, type: 'Password' },
    { pattern: /token|jwt|auth|api.?key/i, type: 'Authentication Token' },
    { pattern: /credit|card|cvv|cvc|ccv|cc.?num|cardnum/i, type: 'Credit Card' },
    { pattern: /ssn|social.?security/i, type: 'Social Security Number' },
    { pattern: /account|routing|bank/i, type: 'Financial Information' },
    { pattern: /address|email|phone|mobile|zip|postal/i, type: 'Personal Information' }
  ];
  
  for (const element of allElements) {
    // Filter only attributes that start with 'data-'
    const dataAttributes = Array.from(element.attributes)
      .filter(attr => attr.name.startsWith('data-'))
      .map(attr => ({ name: attr.name, value: attr.value }));
    
    // Skip if element has no data attributes
    if (dataAttributes.length === 0) continue;
    
    for (const attr of dataAttributes) {
      // Check each sensitive pattern
      for (const pattern of sensitivePatterns) {
        if (pattern.pattern.test(attr.name) || pattern.pattern.test(attr.value)) {
          vulnerabilities.push({
            name: 'Sensitive Data in HTML Attribute',
            description: `Potential ${pattern.type} information found in a data attribute. Sensitive data should not be stored in HTML attributes as it's easily accessible.`,
            severity: 'Medium',
            location: `Element <${element.tagName.toLowerCase()}> with attribute ${attr.name}="${attr.value}"`
          });
          break;
        }
      }
      
      // Check for JWT tokens specifically
      if (attr.value && /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(attr.value)) {
        vulnerabilities.push({
          name: 'JWT Token Exposed in HTML Attribute',
          description: 'A JWT token is exposed in an HTML data attribute. This can be easily accessed by any JavaScript on the page, including potential XSS payloads.',
          severity: 'High',
          location: `Element <${element.tagName.toLowerCase()}> with attribute ${attr.name}`
        });
      }
    }
  }
}

// Enhanced check for exposed API keys
function checkExposedAPIKeys(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  const htmlContent = document.documentElement.innerHTML;
  
  // Common API key patterns
  const apiKeyPatterns = [
    { pattern: /['"]?api[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9]{16,})['"]/, name: 'Generic API Key' },
    { pattern: /['"]?api[_-]?secret['"]?\s*[:=]\s*['"]([a-zA-Z0-9]{16,})['"]/, name: 'API Secret' },
    { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key ID' },
    { pattern: /ghp_[a-zA-Z0-9]{36}/, name: 'GitHub Personal Access Token' },
    { pattern: /AIza[0-9A-Za-z-_]{35}/, name: 'Google API Key' },
    { pattern: /sk_live_[0-9a-zA-Z]{24}/, name: 'Stripe API Key' },
    { pattern: /SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}/, name: 'SendGrid API Key' },
    { pattern: /key-[a-zA-Z0-9]{32}/, name: 'Mailgun API Key' },
    { pattern: /[a-z0-9]{32}-us[0-9]{1,2}/, name: 'Mailchimp API Key' },
    { pattern: /xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/, name: 'Slack API Token' },
    { pattern: /BEGIN\s+PRIVATE\s+KEY/, name: 'Private Key' }
  ];
  
  // Check each API key pattern
  for (const pattern of apiKeyPatterns) {
    // Check in inline scripts
    for (const script of scripts) {
      const matches = script.textContent.match(pattern.pattern);
      if (matches) {
        vulnerabilities.push({
          name: `Exposed ${pattern.name}`,
          description: `A ${pattern.name} appears to be hardcoded in client-side JavaScript. API keys and secrets should never be exposed in client-side code.`,
          severity: 'Critical',
          location: 'JavaScript Code'
        });
      }
    }
    
    // Check in entire HTML (could be outside scripts)
    const htmlMatches = htmlContent.match(pattern.pattern);
    if (htmlMatches && !vulnerabilities.some(v => v.name === `Exposed ${pattern.name}`)) {
      vulnerabilities.push({
        name: `Exposed ${pattern.name}`,
        description: `A ${pattern.name} appears to be exposed in the HTML source. API keys and secrets should never be exposed in client-side code.`,
        severity: 'Critical',
        location: 'HTML Content'
      });
    }
  }
}

// Check for unencrypted client-side data
function checkUnencryptedData(vulnerabilities) {
  try {
    // Check for sensitive data structures in localStorage and sessionStorage
    const storageItems = [
      ...Object.keys(localStorage || {}).map(key => ({ storage: 'localStorage', key, value: localStorage.getItem(key) })),
      ...Object.keys(sessionStorage || {}).map(key => ({ storage: 'sessionStorage', key, value: sessionStorage.getItem(key) }))
    ];
    
    // Patterns for sensitive data
    const sensitiveValuePatterns = [
      { pattern: /^\d{16}$/, type: 'Credit Card Number' },  // 16 digit number
      { pattern: /^\d{3,4}$/, type: 'CVV Code' },           // 3-4 digit number
      { pattern: /^\d{3}-\d{2}-\d{4}$/, type: 'SSN' },      // XXX-XX-XXXX format
      { pattern: /^\d{9}$/, type: 'SSN' },                  // 9 digit number
      { pattern: /base64eyJ/, type: 'Base64 Encoded Data' } // Common pattern for base64 encoded JSON
    ];
    
    // Check for potentially sensitive unencrypted data
    for (const item of storageItems) {
      // Skip items we know are already checked by other functions
      if (item.key.includes('preference') || 
          item.key.includes('theme') || 
          item.key.includes('language')) {
        continue;
      }
      
      // Try to identify JSON data
      if (item.value && item.value.startsWith('{') && item.value.endsWith('}')) {
        try {
          const parsedValue = JSON.parse(item.value);
          
          // Check if JSON contains potentially sensitive fields but no indication of encryption
          const sensitiveKeys = ['password', 'token', 'secret', 'key', 'credit', 'card', 'ssn', 'account'];
          const containsSensitiveKey = Object.keys(parsedValue).some(k => 
            sensitiveKeys.some(sk => k.toLowerCase().includes(sk))
          );
          
          // Check if there are indicators this might be encrypted
          const possiblyEncrypted = 
            (typeof parsedValue.iv === 'string' && typeof parsedValue.ciphertext === 'string') ||
            (typeof parsedValue.salt === 'string' && typeof parsedValue.ct === 'string') ||
            item.key.includes('encrypt') || 
            item.value.includes('cipher');
          
          if (containsSensitiveKey && !possiblyEncrypted) {
            vulnerabilities.push({
              name: 'Unencrypted Sensitive Data in Client Storage',
              description: `${item.storage} contains what appears to be sensitive data in JSON format without encryption.`,
              severity: 'High',
              location: `${item.storage}["${item.key}"]`
            });
          }
        } catch (e) {
          // Not valid JSON, continue checking with other methods
        }
      }
      
      // Check for structured sensitive data
      for (const pattern of sensitiveValuePatterns) {
        if (item.value && pattern.pattern.test(item.value)) {
          vulnerabilities.push({
            name: `Potential ${pattern.type} Stored Unencrypted`,
            description: `${item.storage} contains what appears to be a ${pattern.type} stored in plaintext.`,
            severity: 'High',
            location: `${item.storage}["${item.key}"]`
          });
        }
      }
    }
  } catch (e) {
    console.log('Error checking for unencrypted data:', e);
  }
}

// Check for JavaScript-specific vulnerabilities like prototype pollution
function checkJavaScriptVulnerabilities(vulnerabilities) {
  // Get all scripts
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for prototype pollution vulnerabilities
  checkPrototypePollution(scriptContent, vulnerabilities);
  
  // Check for other JavaScript security issues
  checkUnsafeEval(scriptContent, vulnerabilities);
  checkReDoS(scriptContent, vulnerabilities);
  checkDeepMergeVulnerability(scriptContent, vulnerabilities);
}

// Check for prototype pollution vulnerabilities
function checkPrototypePollution(scriptContent, vulnerabilities) {
  // Common patterns that may indicate prototype pollution vulnerabilities
  const prototypeAccessPatterns = [
    { pattern: /Object\.prototype\.\w+\s*=/, name: 'Direct Object.prototype Modification' },
    { pattern: /\.__proto__\s*=/, name: '__proto__ Assignment' },
    { pattern: /\[['"]__proto__['"]\]\s*=/, name: 'Bracket __proto__ Assignment' },
    { pattern: /\.constructor\.prototype/, name: 'constructor.prototype Access' },
    { pattern: /Object\.assign\s*\([^,)]+,\s*(?:JSON\.parse|req\.body|req\.query|req\.params|location)/, name: 'Unsafe Object.assign with User Input' },
    { pattern: /\$\.extend\s*\([^,)]+,\s*(?:JSON\.parse|req\.body|req\.query|req\.params|location)/, name: 'Unsafe jQuery.extend with User Input' }
  ];
  
  // Search for each pattern
  for (const pattern of prototypeAccessPatterns) {
    if (pattern.pattern.test(scriptContent)) {
      vulnerabilities.push({
        name: 'Potential Prototype Pollution Vulnerability',
        description: `Code contains ${pattern.name} which may lead to prototype pollution if user input can reach this code.`,
        severity: 'High',
        location: 'JavaScript Code'
      });
    }
  }
  
  // Check for unsafe recursive merge functions
  if ((scriptContent.includes('merge') || scriptContent.includes('extend') || scriptContent.includes('assign')) &&
      (scriptContent.includes('__proto__') || scriptContent.includes('prototype'))) {
    
    // Look for common merge/extend functions
    if (scriptContent.match(/function\s+(?:deep)?(?:Merge|merge|Extend|extend)/)) {
      vulnerabilities.push({
        name: 'Potential Recursive Merge Prototype Pollution',
        description: 'Custom merge or extend function detected that might be vulnerable to prototype pollution if it handles objects recursively without proper sanitization.',
        severity: 'Medium',
        location: 'JavaScript Code'
      });
    }
  }
}

// Check for unsafe eval usage
function checkUnsafeEval(scriptContent, vulnerabilities) {
  // Check for eval with dynamic input
  if (scriptContent.match(/eval\s*\([^)]*(?:input|value|innerHTML|parameter|query|param|request|response|data)/i)) {
    vulnerabilities.push({
      name: 'Unsafe eval() with Dynamic Input',
      description: 'Code uses eval() with potentially dynamic input, which could lead to code injection vulnerabilities.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for new Function with dynamic input
  if (scriptContent.match(/new\s+Function\s*\([^)]*(?:input|value|innerHTML|parameter|query|param|request|response|data)/i)) {
    vulnerabilities.push({
      name: 'Unsafe Function Constructor with Dynamic Input',
      description: 'Code uses new Function() with potentially dynamic input, which could lead to code injection vulnerabilities.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
}

// Check for potential ReDoS (Regular Expression Denial of Service) vulnerabilities
function checkReDoS(scriptContent, vulnerabilities) {
  // Patterns that might indicate vulnerable regex
  const vulnerableRegexPatterns = [
    { pattern: /\(\.\*\)\+/, name: 'Nested Repetition Quantifiers' }, 
    { pattern: /\[\^.*\]\*\+/, name: 'Negated Character Set with Repetition' },
    { pattern: /\.\*\.\*/, name: 'Multiple Wildcards' },
    { pattern: /\(\.\*\|\.\*\)/, name: 'Alternation with Wildcards' },
    { pattern: /\(\.\*\)\{\d+,\}/, name: 'Unbounded Repetition' }
  ];
  
  // Find regex literals or RegExp constructors
  const regexMatches = scriptContent.match(/\/(?:\\.|[^\/])+\/[gim]*|new\s+RegExp\s*\([^)]+\)/g) || [];
  
  // Check each regex for vulnerable patterns
  for (const regexMatch of regexMatches) {
    for (const pattern of vulnerableRegexPatterns) {
      if (pattern.pattern.test(regexMatch)) {
        vulnerabilities.push({
          name: 'Potential ReDoS Vulnerability',
          description: `Regular expression contains ${pattern.name} which may be vulnerable to Regular Expression Denial of Service (ReDoS) attacks.`,
          severity: 'Medium',
          location: `Regex: ${regexMatch}`
        });
        break;
      }
    }
  }
}

// Check for common deep merge vulnerabilities that can lead to prototype pollution
function checkDeepMergeVulnerability(scriptContent, vulnerabilities) {
  // Common vulnerable deep merge libraries/functions
  const vulnerableMergePatterns = [
    { pattern: /lodash\.merge|_\.merge/, name: 'Lodash merge (versions < 4.17.21)' },
    { pattern: /jquery\.extend\s*\(\s*true/, name: 'jQuery.extend with deep copy (versions < 3.5.0)' },
    { pattern: /\$\.extend\s*\(\s*true/, name: 'jQuery.extend with deep copy (versions < 3.5.0)' }
  ];
  
  // Check for each vulnerable pattern
  for (const pattern of vulnerableMergePatterns) {
    if (pattern.pattern.test(scriptContent)) {
      vulnerabilities.push({
        name: 'Potential Deep Merge Vulnerability',
        description: `Code uses ${pattern.name} which may be vulnerable to prototype pollution if used with untrusted data.`,
        severity: 'Medium',
        location: 'JavaScript Code'
      });
    }
  }
}

// Check for improper authentication token handling
function checkAuthTokenHandling(vulnerabilities) {
  // Check for tokens in storage
  checkTokensInStorage(vulnerabilities);
  
  // Check for secure token configuration
  checkTokenConfiguration(vulnerabilities);
  
  // Check for server-client token validation issues
  checkTokenValidation(vulnerabilities);
}

// Check for authentication tokens in storage
function checkTokensInStorage(vulnerabilities) {
  try {
    // Check localStorage for tokens
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      
      // Check for JWT tokens
      if (value && typeof value === 'string' && 
          /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(value)) {
        
        try {
          // Try to decode the token payload
          const payload = JSON.parse(atob(value.split('.')[1]));
          
          // Check if token contains sensitive claims
          const sensitiveClaims = ['sub', 'role', 'permissions', 'email', 'groups', 'admin', 'scope'];
          const hasSensitiveClaims = Object.keys(payload).some(claim => 
            sensitiveClaims.some(sc => claim.toLowerCase().includes(sc))
          );
          
          // Check for expiration
          const hasExpiration = payload.exp !== undefined;
          
          // Check for additional security concerns
          if (hasSensitiveClaims && !hasExpiration) {
            vulnerabilities.push({
              name: 'JWT Token Without Expiration',
              description: 'JWT token contains sensitive claims but does not have an expiration time (exp claim), making it valid indefinitely.',
              severity: 'Medium',
              location: `localStorage["${key}"]`
            });
          }
          
          // Check for very long expiration time
          if (hasExpiration) {
            const expirationDate = new Date(payload.exp * 1000);
            const now = new Date();
            const monthsToExpire = (expirationDate - now) / (1000 * 60 * 60 * 24 * 30);
            
            if (monthsToExpire > 6) {
              vulnerabilities.push({
                name: 'JWT Token with Excessive Expiration Time',
                description: `JWT token has an excessive expiration time (${Math.round(monthsToExpire)} months), increasing the window of opportunity for token theft.`,
                severity: 'Low',
                location: `localStorage["${key}"]`
              });
            }
          }
          
          // Check for missing token type
          if (!key.toLowerCase().includes('refresh') && !payload.type && hasSensitiveClaims) {
            vulnerabilities.push({
              name: 'JWT Token Missing Type Claim',
              description: 'JWT access token does not specify a "type" claim, making it difficult to distinguish between access and refresh tokens.',
              severity: 'Low',
              location: `localStorage["${key}"]`
            });
          }
        } catch (e) {
          // Error parsing JWT, continue
        }
      }
    }
    
    // Check if access token and refresh token are both stored in localStorage
    const hasAccessToken = Array.from({length: localStorage.length}, (_, i) => localStorage.key(i))
      .some(key => key.toLowerCase().includes('access') && key.toLowerCase().includes('token'));
    
    const hasRefreshToken = Array.from({length: localStorage.length}, (_, i) => localStorage.key(i))
      .some(key => key.toLowerCase().includes('refresh') && key.toLowerCase().includes('token'));
    
    if (hasAccessToken && hasRefreshToken) {
      vulnerabilities.push({
        name: 'Both Access and Refresh Tokens in localStorage',
        description: 'Both access and refresh tokens are stored in localStorage. Refresh tokens should be stored in secure HttpOnly cookies to prevent access by JavaScript.',
        severity: 'Medium',
        location: 'localStorage'
      });
    }
  } catch (e) {
    console.log('Error checking tokens in storage:', e);
  }
}

// Check for token configuration issues
function checkTokenConfiguration(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for common token configuration issues in code
  
  // Lack of token validation
  if (scriptContent.match(/token|jwt|auth/i) && 
      !scriptContent.match(/verify|validate|check|isValid/i)) {
    
    vulnerabilities.push({
      name: 'Potential Missing Token Validation',
      description: 'Code appears to use authentication tokens but may not properly validate them before use.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // Client-side token generation
  if ((scriptContent.match(/generate.*token|create.*token|sign.*token|new.*token/i) || 
       scriptContent.match(/jwt\.sign/)) && !scriptContent.includes('Service Worker')) {
    
    vulnerabilities.push({
      name: 'Client-Side Token Generation',
      description: 'Code appears to generate authentication tokens on the client side. Token creation should occur server-side only.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for token refresh mechanisms that don't validate old tokens
  if (scriptContent.match(/refresh.*token/i) && 
      !scriptContent.match(/verify.*before|validate.*before|check.*before/i)) {
    
    vulnerabilities.push({
      name: 'Insecure Token Refresh Mechanism',
      description: 'Token refresh logic may not validate the existing token before requesting a new one, which could allow token refresh attacks.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
}

// Check for token validation issues
function checkTokenValidation(vulnerabilities) {
  // Get the network requests using performance API
  if (window.performance && performance.getEntriesByType) {
    const resources = performance.getEntriesByType('resource');
    
    // Check for authentication endpoints
    for (const resource of resources) {
      const url = resource.name.toLowerCase();
      
      // Check for potential authentication endpoints
      if (url.includes('auth') || url.includes('login') || url.includes('token') || url.includes('signin')) {
        // Check if request was made over HTTPS
        if (!url.startsWith('https:')) {
          vulnerabilities.push({
            name: 'Authentication Over Insecure Connection',
            description: 'Authentication request made over insecure HTTP connection. All authentication traffic should use HTTPS.',
            severity: 'Critical',
            location: resource.name
          });
        }
      }
    }
  }
  
  // Check for token usage in URL (very bad practice)
  const currentUrl = window.location.href;
  if (/[?&](token|jwt|auth)=/i.test(currentUrl)) {
    vulnerabilities.push({
      name: 'Authentication Token in URL',
      description: 'Authentication token included in URL parameters. This exposes the token in browser history, server logs, and referer headers.',
      severity: 'High',
      location: 'URL: ' + currentUrl.split('?')[0] + '?...'
    });
  }
}

// Check for unsafe event listener implementations
function checkUnsafeEventListeners(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for event listeners that may use eval or other dangerous patterns
  if (scriptContent.match(/addEventListener\s*\([^)]*,\s*function[^{]*\{[^}]*eval\s*\(/i) ||
      scriptContent.match(/addEventListener\s*\([^)]*,\s*function[^{]*\{[^}]*new\s+Function\s*\(/i)) {
    vulnerabilities.push({
      name: 'Unsafe Event Listener Implementation',
      description: 'Event listener contains potentially dangerous code evaluation (eval or Function constructor), which could lead to code injection vulnerabilities.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for listeners on sensitive events without proper validation
  if (scriptContent.match(/addEventListener\s*\(\s*['"]message['"]/) && 
      !scriptContent.match(/\.origin\s*===|\.origin\s*==|event\.source/i)) {
    vulnerabilities.push({
      name: 'Insecure Message Event Handling',
      description: 'Message event listener does not validate the origin of messages, which could allow cross-origin attacks.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for listeners that may directly use event data in dangerous contexts
  if (scriptContent.match(/addEventListener\s*\([^)]*,\s*function[^{]*\{[^}]*innerHTML\s*=\s*[^;]*event/i) ||
      scriptContent.match(/addEventListener\s*\([^)]*,\s*function[^{]*\{[^}]*document\.write\s*\([^)]*event/i)) {
    vulnerabilities.push({
      name: 'Unsafe Event Data Handling',
      description: 'Event listener appears to directly use event data for DOM manipulation without proper sanitization, which could enable XSS attacks.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for direct use of user input in event listeners
  const eventListenerElements = document.querySelectorAll('*[onclick], *[onmouseover], *[onmousedown], *[onkeydown], *[onkeypress], *[onkeyup], *[onchange], *[oninput]');
  
  for (const element of eventListenerElements) {
    const attributes = element.attributes;
    
    for (let i = 0; i < attributes.length; i++) {
      const attr = attributes[i];
      
      if (attr.name.startsWith('on') && 
          (attr.value.includes('this.value') || attr.value.includes('value') || attr.value.includes('this.innerText'))) {
        vulnerabilities.push({
          name: 'Unsafe Inline Event Handler',
          description: 'Inline event handler appears to directly use input values without sanitization, which could enable XSS attacks.',
          severity: 'Medium',
          location: `Element ${element.tagName.toLowerCase()} with ${attr.name}="${attr.value}"`
        });
        break; // Only report once per element
      }
    }
  }
}

// Check for improper input validation beyond XSS
function checkImproperInputValidation(vulnerabilities) {
  // Check for numeric inputs without proper validation
  const numberInputs = document.querySelectorAll('input[type="number"]');
  
  for (const input of numberInputs) {
    if (!input.hasAttribute('min') && !input.hasAttribute('max')) {
      vulnerabilities.push({
        name: 'Unbounded Numeric Input',
        description: 'Numeric input field has no minimum or maximum constraints, which could allow integer overflow/underflow attacks or resource exhaustion.',
        severity: 'Low',
        location: `Input field ${input.name ? 'name="' + input.name + '"' : (input.id ? 'id="' + input.id + '"' : '')}`
      });
    }
  }
  
  // Check for file inputs without type restrictions
  const fileInputs = document.querySelectorAll('input[type="file"]');
  
  for (const input of fileInputs) {
    if (!input.hasAttribute('accept')) {
      vulnerabilities.push({
        name: 'Unrestricted File Upload',
        description: 'File upload field does not restrict file types, which could allow uploading of malicious files.',
        severity: 'Medium',
        location: `File input ${input.name ? 'name="' + input.name + '"' : (input.id ? 'id="' + input.id + '"' : '')}`
      });
    }
  }
  
  // Check for email inputs without pattern validation
  const emailInputs = document.querySelectorAll('input[type="email"]');
  
  for (const input of emailInputs) {
    const form = input.closest('form');
    // Look for form validation code
    if (form && !form.hasAttribute('novalidate')) {
      // Browser validation might be sufficient
    } else if (!input.hasAttribute('pattern')) {
      vulnerabilities.push({
        name: 'Weak Email Validation',
        description: 'Email input field may not be properly validated, as form validation is disabled and no pattern attribute is specified.',
        severity: 'Low',
        location: `Email input ${input.name ? 'name="' + input.name + '"' : (input.id ? 'id="' + input.id + '"' : '')}`
      });
    }
  }
  
  // Check for forms with potential search injection issues
  const searchForms = Array.from(document.querySelectorAll('form')).filter(form => {
    const action = form.getAttribute('action') || '';
    const inputs = form.querySelectorAll('input');
    return action.includes('search') || 
           [...inputs].some(input => input.name && input.name.includes('search') || 
                           input.id && input.id.includes('search') ||
                           input.placeholder && input.placeholder.toLowerCase().includes('search'));
  });
  
  for (const form of searchForms) {
    // Check if search parameters are sanitized
    const scripts = document.querySelectorAll('script');
    let foundSearchSanitization = false;
    
    for (const script of scripts) {
      if (script.textContent && 
          (script.textContent.includes('sanitize') || script.textContent.includes('escape')) && 
          script.textContent.includes('search')) {
        foundSearchSanitization = true;
        break;
      }
    }
    
    if (!foundSearchSanitization) {
      vulnerabilities.push({
        name: 'Potential Search Injection',
        description: 'Search form may not properly sanitize input, which could lead to search injection attacks (e.g., XSS or SQL injection).',
        severity: 'Medium',
        location: `Search form ${form.id ? 'id="' + form.id + '"' : (form.getAttribute('action') ? 'action="' + form.getAttribute('action') + '"' : '')}`
      });
    }
  }
}

// Check for DOM manipulation risks
function checkDOMManipulationRisks(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for DOM clobbering vulnerabilities
  if (scriptContent.match(/document\.getElementById\s*\([^)]+\)(?!\s*instanceof)/i) &&
      scriptContent.match(/\[\s*(['"])id\1\s*\]/i)) {
    vulnerabilities.push({
      name: 'Potential DOM Clobbering Vulnerability',
      description: 'Code may be vulnerable to DOM clobbering attacks, where attacker-controlled HTML can override JavaScript object properties using named DOM elements.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // Check for innerHTML usage with dynamic content
  if (scriptContent.match(/\.innerHTML\s*=\s*[^;]*\+/i) ||
      scriptContent.match(/\.innerHTML\s*\+=/) ||
      scriptContent.match(/\.outerHTML\s*=\s*[^;]*\+/i)) {
    vulnerabilities.push({
      name: 'Unsafe Dynamic Content Insertion',
      description: 'Code uses innerHTML/outerHTML with concatenated strings, which can lead to XSS vulnerabilities if any part of the string is user-controlled.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for insertAdjacentHTML with dynamic content
  if (scriptContent.match(/\.insertAdjacentHTML\s*\(\s*['"]beforeend['"],\s*[^;]*\+/i) ||
      scriptContent.match(/\.insertAdjacentHTML\s*\(\s*['"]afterbegin['"],\s*[^;]*\+/i)) {
    vulnerabilities.push({
      name: 'Unsafe insertAdjacentHTML Usage',
      description: 'Code uses insertAdjacentHTML with concatenated strings, which can lead to XSS vulnerabilities if any part of the string is user-controlled.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for document.domain modification
  if (scriptContent.match(/document\.domain\s*=/i)) {
    vulnerabilities.push({
      name: 'Document Domain Modification',
      description: 'Code modifies document.domain, which can weaken the same-origin policy and lead to security vulnerabilities.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for element attribute manipulation with dynamic content
  if (scriptContent.match(/\.setAttribute\s*\(\s*['"](?:href|src|action|formaction|xlink:href)['"],\s*[^;]*\+/i)) {
    vulnerabilities.push({
      name: 'Unsafe Attribute Manipulation',
      description: 'Code sets security-sensitive attributes with concatenated strings, which can lead to XSS or open redirect vulnerabilities.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check for risky document.write usage
  if (scriptContent.match(/document\.write(?:ln)?\s*\([^)]*\+/i) || 
      scriptContent.match(/document\.write(?:ln)?\s*\([^)]*location/i) ||
      scriptContent.match(/document\.write(?:ln)?\s*\([^)]*window\./i)) {
    vulnerabilities.push({
      name: 'Unsafe document.write Usage',
      description: 'Code uses document.write with dynamic content, which can lead to XSS vulnerabilities and is discouraged for performance reasons.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
}

// Check for network-related vulnerabilities
function checkNetworkVulnerabilities(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for JSONP usage, which can have security implications
  if (scriptContent.match(/&callback=|[?]callback=|&jsonp=|[?]jsonp=/i) || 
      scriptContent.match(/\.appendChild\s*\(\s*script\s*\).*callback/i)) {
    vulnerabilities.push({
      name: 'JSONP Usage Detected',
      description: 'Code appears to use JSONP for cross-origin requests, which can lead to security issues if the external API is not trusted.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // Check for insecure WebSocket connections
  if (scriptContent.match(/new\s+WebSocket\s*\(\s*['"]ws:\/\//i)) {
    vulnerabilities.push({
      name: 'Insecure WebSocket Connection',
      description: 'Code establishes WebSocket connections over unencrypted ws:// protocol instead of secure wss://',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
  
  // Check if sensitive operations are protected against CSRF
  const forms = document.querySelectorAll('form');
  
  for (const form of forms) {
    const method = form.getAttribute('method') || 'get';
    if (method.toLowerCase() === 'post') {
      let hasCSRFToken = false;
      
      // Check for hidden input that might be a CSRF token
      const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
      for (const input of hiddenInputs) {
        const name = input.getAttribute('name') || '';
        if (name.toLowerCase().includes('token') || 
            name.toLowerCase().includes('csrf') || 
            name.toLowerCase().includes('xsrf')) {
          hasCSRFToken = true;
          break;
        }
      }
      
      if (!hasCSRFToken) {
        vulnerabilities.push({
          name: 'Potential CSRF Vulnerability',
          description: 'Form submits POST requests without an apparent CSRF token, which could allow cross-site request forgery attacks.',
          severity: 'Medium',
          location: `Form ${form.id ? 'id="' + form.id + '"' : (form.getAttribute('action') ? 'action="' + form.getAttribute('action') + '"' : '')}`
        });
      }
    }
  }
  
  // Check for open redirects
  if (scriptContent.match(/location\s*=|location\.href\s*=|location\.replace\s*\(|location\.assign\s*\(/i) && 
      scriptContent.match(/\blocation\b.*\b(search|hash|href|URL|document\.URL)\b/i)) {
    vulnerabilities.push({
      name: 'Potential Open Redirect',
      description: 'Code appears to redirect users based on URL parameters, which could be manipulated to redirect to malicious sites.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // Check for credentials in fetch/XHR requests
  if (scriptContent.match(/fetch\s*\([^)]*,\s*\{[^}]*credentials\s*:\s*['"]include['"]/i) ||
      scriptContent.match(/\.withCredentials\s*=\s*true/i)) {
    // This isn't always a vulnerability, but worth noting if CORS is misconfigured
    vulnerabilities.push({
      name: 'Cross-Origin Requests with Credentials',
      description: 'Code sends cross-origin requests with credentials. If combined with permissive CORS configuration on the server, this could lead to security issues.',
      severity: 'Low',
      location: 'JavaScript Code'
    });
  }
}

// Check for API security issues
function checkAPISecurityIssues(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for sensitive API endpoints in JavaScript
  const sensitiveEndpointPatterns = [
    { pattern: /\/users\/|\/user\/|\/accounts\/|\/account\//i, name: 'User/Account Endpoint' },
    { pattern: /\/login|\/authenticate|\/signin|\/signup|\/register/i, name: 'Authentication Endpoint' },
    { pattern: /\/admin|\/dashboard|\/manage/i, name: 'Admin/Management Endpoint' },
    { pattern: /\/payment|\/checkout|\/cart|\/order/i, name: 'Payment/Order Endpoint' },
    { pattern: /\/api\/v\d+\//i, name: 'Versioned API Endpoint' }
  ];
  
  // Look for direct API URLs in JavaScript
  for (const pattern of sensitiveEndpointPatterns) {
    if (pattern.pattern.test(scriptContent)) {
      const apiUrlMatch = scriptContent.match(/(https?:\/\/[^'"\s]+)(\/api\/|\/v\d+\/|\/rest\/|\/graphql|\/gql)[^'"\s]*/i);
      if (apiUrlMatch) {
        vulnerabilities.push({
          name: 'Exposed API Endpoint',
          description: `Code exposes what appears to be a ${pattern.name}. Ensure this doesn't reveal sensitive information about your API structure.`,
          severity: 'Low',
          location: `API endpoint: ${apiUrlMatch[0]}`
        });
      }
    }
  }
  
  // Check for hardcoded API configuration that might be sensitive
  if (scriptContent.match(/apiKey|api_key|apiSecret|api_secret|client_id|client_secret/i) && 
      scriptContent.match(/config|configuration|settings|setup|init/i)) {
    vulnerabilities.push({
      name: 'API Configuration in Client-Side Code',
      description: 'API configuration information appears to be included in client-side code, which might expose sensitive implementation details.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // Check for GraphQL-specific vulnerabilities
  if (scriptContent.includes('/graphql') || scriptContent.includes('/gql')) {
    // Check for potential GraphQL introspection
    if (scriptContent.includes('__schema') || scriptContent.includes('IntrospectionQuery')) {
      vulnerabilities.push({
        name: 'GraphQL Introspection Enabled',
        description: 'Code appears to use GraphQL introspection queries, which might expose the complete API schema to potential attackers if not properly restricted in production.',
        severity: 'Medium',
        location: 'JavaScript Code'
      });
    }
    
    // Check for unbatched GraphQL queries
    if (!scriptContent.match(/\[\s*\{\s*query/) && scriptContent.match(/\{\s*query/)) {
      vulnerabilities.push({
        name: 'Unbatched GraphQL Queries',
        description: 'GraphQL API appears to be used without query batching, which could make it more vulnerable to DoS attacks.',
        severity: 'Low',
        location: 'JavaScript Code'
      });
    }
  }
  
  // Check for potential API rate limiting bypass
  // Look for multiple similar API calls in loops
  if ((scriptContent.match(/for\s*\([^)]+\)\s*\{[^}]*fetch\s*\(/i) || 
       scriptContent.match(/for\s*\([^)]+\)\s*\{[^}]*\.ajax\s*\(/i) ||
       scriptContent.match(/for\s*\([^)]+\)\s*\{[^}]*\.get\s*\(/i) ||
       scriptContent.match(/for\s*\([^)]+\)\s*\{[^}]*\.post\s*\(/i) ||
       scriptContent.match(/while\s*\([^)]+\)\s*\{[^}]*fetch\s*\(/i)) &&
      !scriptContent.match(/setTimeout|setInterval|requestAnimationFrame/i)) {
    vulnerabilities.push({
      name: 'Potential API Rate Limiting Bypass',
      description: 'Code appears to make multiple API requests in a loop without rate limiting or delays, which could lead to API abuse.',
      severity: 'Medium',
      location: 'JavaScript Code'
    });
  }
  
  // Check for insecure response handling
  if (scriptContent.match(/\.then\s*\([^)]*eval/i) || 
      scriptContent.match(/\.then\s*\([^)]*Function/i) ||
      scriptContent.match(/\.then\s*\([^)]*document\.write/i)) {
    vulnerabilities.push({
      name: 'Insecure API Response Handling',
      description: 'Code appears to process API responses using unsafe methods (eval, Function constructor, or document.write), which could lead to code injection if the API is compromised.',
      severity: 'High',
      location: 'JavaScript Code'
    });
  }
}

// Check for unvalidated API endpoints
function checkUnvalidatedAPIEndpoints(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Look for API calls patterns
  const apiCallPatterns = [
    { pattern: /fetch\s*\(['"](\/api\/|http)/i, name: 'Fetch API' },
    { pattern: /\$\.(?:get|post|ajax|put|delete)\s*\(['"](\/api\/|http)/i, name: 'jQuery AJAX' },
    { pattern: /axios\.(?:get|post|put|delete|request)\s*\(['"](\/api\/|http)/i, name: 'Axios' },
    { pattern: /new\s+XMLHttpRequest\(\).*\.open\s*\(['"](?:GET|POST|PUT|DELETE)['"],\s*['"](\/api\/|http)/i, name: 'XMLHttpRequest' }
  ];
  
  // Check for input validation in API calls
  for (const pattern of apiCallPatterns) {
    if (pattern.pattern.test(scriptContent)) {
      // Look for validation before making API calls
      const hasPreCallValidation = 
        scriptContent.match(/validate.*before.*\.(fetch|ajax|get|post|send)/i) ||
        scriptContent.match(/sanitize.*before.*\.(fetch|ajax|get|post|send)/i) ||
        scriptContent.match(/verify.*before.*\.(fetch|ajax|get|post|send)/i);
      
      // Look for request payload validation
      const hasPayloadValidation =
        scriptContent.match(/validate\s*\(\s*(?:data|payload|body|params)/i) ||
        scriptContent.match(/sanitize\s*\(\s*(?:data|payload|body|params)/i) ||
        scriptContent.match(/check\s*\(\s*(?:data|payload|body|params)/i);
      
      if (!hasPreCallValidation && !hasPayloadValidation && 
          scriptContent.match(/\.value|document\.getElementById|querySelector.*\.value|formData|new FormData/i)) {
        
        vulnerabilities.push({
          name: 'Potential Unvalidated API Endpoint Call',
          description: `Code appears to make ${pattern.name} calls with data from form inputs without validation, which could lead to injection attacks or API misuse.`,
          severity: 'Medium',
          location: 'JavaScript Code - API Calls'
        });
        break; // Only report once for this type of API call
      }
    }
  }
  
  // Check for client-side path parameters manipulation
  if ((scriptContent.match(/fetch\s*\([^)]*\$\{/i) || 
      scriptContent.match(/\.\s*(?:get|post|ajax|put|delete)\s*\([^)]*\$\{/i) ||
      scriptContent.match(/\.open\s*\([^)]*\$\{/i)) &&
      scriptContent.match(/location|window\.location|param|parameter|id|userId|projectId/i)) {
    
    // Look for validation of path parameters
    const hasPathParamValidation =
      scriptContent.match(/validate.*id/i) ||
      scriptContent.match(/sanitize.*param/i) ||
      scriptContent.match(/parseInt\s*\(|Number\s*\(/i) ||
      scriptContent.match(/toString\s*\(\s*\)/i);
    
    if (!hasPathParamValidation) {
      vulnerabilities.push({
        name: 'Unvalidated Path Parameter in API Call',
        description: 'Code appears to include potentially user-controlled path parameters in API calls without validation, which could lead to path traversal or injection attacks.',
        severity: 'High',
        location: 'JavaScript Code - API Path Parameters'
      });
    }
  }
  
  // Check for GraphQL query validation
  if (scriptContent.includes('graphql') || scriptContent.includes('gql')) {
    const hasGraphQLValidation = 
      scriptContent.match(/validate.*(?:query|mutation)/i) || 
      scriptContent.match(/sanitize.*(?:variables|params)/i);
      
    if (!hasGraphQLValidation && 
        (scriptContent.match(/variables\s*:/) || scriptContent.match(/\$\{.*\}/))) {
      vulnerabilities.push({
        name: 'Unvalidated GraphQL Query Variables',
        description: 'GraphQL queries appear to use variables without proper validation, which could lead to injection attacks.',
        severity: 'Medium',
        location: 'JavaScript Code - GraphQL'
      });
    }
  }
}

// Check for improper authentication checks
function checkImproperAuthenticationChecks(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for client-side authentication logic
  if (scriptContent.match(/function\s+(?:is|check|verify)(?:User|Admin|Authenticated|LoggedIn)/i) ||
      scriptContent.match(/(?:is|check|verify)(?:User|Admin|Authenticated|LoggedIn)\s*=\s*function/i)) {
    
    vulnerabilities.push({
      name: 'Client-Side Authentication Logic',
      description: 'Authentication checks appear to be implemented in client-side JavaScript, which can be easily bypassed. Authentication should be handled server-side.',
      severity: 'Critical',
      location: 'JavaScript Code - Authentication Logic'
    });
  }
  
  // Check for authentication state stored only in localStorage or sessionStorage
  if ((scriptContent.match(/localStorage\.(?:set|get)Item\s*\(\s*['"](?:token|auth|authenticated|user|logged|admin)['"]/i) ||
       scriptContent.match(/sessionStorage\.(?:set|get)Item\s*\(\s*['"](?:token|auth|authenticated|user|logged|admin)['"]/i)) &&
      scriptContent.match(/if\s*\(\s*(?:localStorage|sessionStorage)\.(?:getItem|get)\s*\(/i)) {
    
    vulnerabilities.push({
      name: 'Client-Side Authentication State Storage',
      description: 'Authentication state appears to be stored and checked only on the client side. This can be easily manipulated by users to bypass authentication.',
      severity: 'High',
      location: 'JavaScript Code - Authentication State'
    });
  }
  
  // Check for hardcoded credentials
  if (scriptContent.match(/password\s*(?:===|==|=)\s*['"].*['"]/i) ||
      scriptContent.match(/username\s*(?:===|==|=)\s*['"].*['"]/i) ||
      scriptContent.match(/user\s*(?:===|==|=)\s*['"]admin['"]/i) ||
      scriptContent.match(/role\s*(?:===|==|=)\s*['"]admin['"]/i)) {
    
    vulnerabilities.push({
      name: 'Hardcoded Credentials or Role Checks',
      description: 'Hardcoded credentials or role checks were found in client-side code, which can be easily discovered and exploited.',
      severity: 'Critical',
      location: 'JavaScript Code - Hardcoded Auth Checks'
    });
  }
  
  // Check for improper handling of authentication failures
  if (scriptContent.match(/catch\s*\(\s*[^)]+\)\s*\{[^}]*console\.log/i) &&
      scriptContent.match(/login|authenticate|signin|token/i)) {
    
    vulnerabilities.push({
      name: 'Improper Authentication Error Handling',
      description: 'Authentication errors appear to be logged to the console, which may reveal sensitive information about the authentication process.',
      severity: 'Medium',
      location: 'JavaScript Code - Auth Error Handling'
    });
  }
  
  // Check for unsubmitted credentials in forms
  const forms = document.querySelectorAll('form');
  for (const form of forms) {
    if (form.querySelector('input[type="password"]')) {
      const loginButton = form.querySelector('button[type="button"], input[type="button"]');
      if (loginButton) {
        // Check if form has a submit button or uses an onclick handler
        if (!form.querySelector('button[type="submit"], input[type="submit"]') && 
            loginButton.hasAttribute('onclick')) {
          vulnerabilities.push({
            name: 'Form Submission Bypass',
            description: 'Login form appears to use a button with onClick handler instead of proper form submission, which may bypass built-in browser security.',
            severity: 'Medium',
            location: `Form ${form.id ? 'id="' + form.id + '"' : (form.getAttribute('action') ? 'action="' + form.getAttribute('action') + '"' : '')}`
          });
        }
      }
    }
  }
}

// Check for insecure direct object references (IDOR)
function checkInsecureDirectObjectReferences(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for URL patterns that suggest direct object access
  if (window.location.href.match(/[?&](?:id|user_id|document_id|file_id|order_id)=\d+/i)) {
    // Look for authorization checks related to these IDs
    const hasAuthorizationCheck = 
      scriptContent.match(/checkAccess|checkPermission|canAccess|hasPermission|authorize|isAuthorized/i) &&
      (scriptContent.match(/\.then\s*\(\s*function/i) || scriptContent.match(/await/i));
    
    if (!hasAuthorizationCheck) {
      vulnerabilities.push({
        name: 'Potential Insecure Direct Object Reference (IDOR)',
        description: 'Page URL contains an ID parameter but no authorization checks were detected. This could allow users to access unauthorized resources by changing the ID value.',
        severity: 'High',
        location: 'URL Parameter - ' + window.location.href
      });
    }
  }
  
  // Check for client-side data access patterns that suggest IDOR vulnerability
  if ((scriptContent.match(/fetch\s*\([^)]*(?:\/users\/|\/user\/|\/accounts\/|\/account\/|\/profiles\/|\/profile\/)/i) ||
       scriptContent.match(/get\s*\([^)]*(?:\/users\/|\/user\/|\/accounts\/|\/account\/|\/profiles\/|\/profile\/)/i)) &&
      scriptContent.match(/\$\{.*id.*\}/i)) {
    
    // Look for access control checks
    const hasAccessControl = 
      scriptContent.match(/check.*(?:permission|access|role)/i) ||
      scriptContent.match(/is.*(?:owner|authorized|allowed)/i);
    
    if (!hasAccessControl) {
      vulnerabilities.push({
        name: 'Potential IDOR in API Calls',
        description: 'Code fetches user/account data using an ID that appears to be manipulable without proper authorization checks.',
        severity: 'High',
        location: 'JavaScript Code - API Access Pattern'
      });
    }
  }
  
  // Check for client-side data filtering
  if (scriptContent.match(/filter\s*\(\s*([^)]*)\s*=>\s*.*\.id\s*===\s*(?:userId|currentUser)/i) || 
      scriptContent.match(/if\s*\(\s*data\.(?:user|owner|creator)(?:Id|_id)\s*===\s*(?:userId|currentUser)/i)) {
    
    vulnerabilities.push({
      name: 'Client-Side Access Control',
      description: 'Data access control appears to be implemented on the client side by filtering data after retrieval. This can be bypassed since users can access the unfiltered API responses.',
      severity: 'High',
      location: 'JavaScript Code - Client-Side Filtering'
    });
  }
  
  // Check for predictable resource URLs 
  const resourceLinks = document.querySelectorAll('a[href*="/download/"], a[href*="/file/"], a[href*="/document/"], a[href*="/report/"]');
  for (const link of resourceLinks) {
    const href = link.getAttribute('href');
    if (href && href.match(/\d+/)) {
      vulnerabilities.push({
        name: 'Predictable Resource URL',
        description: 'Resource URL contains a numeric ID that might be susceptible to IDOR if server-side authorization checks are not in place.',
        severity: 'Medium',
        location: `Resource link: ${href}`
      });
      break; // Only report once for this type of issue
    }
  }
}

// Check for rate limiting bypass attempts
function checkRateLimitingBypass(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // We already check for this in API Security Issues, but we'll add more specific checks here
  
  // Check for concurrent requests without delay
  if (scriptContent.match(/Promise\.all\s*\(\s*\[/i) && 
      (scriptContent.match(/fetch\s*\(/gi) || scriptContent.match(/\.post\s*\(/gi) || scriptContent.match(/\.get\s*\(/gi)) &&
      scriptContent.match(/for\s*\(/i)) {
    
    vulnerabilities.push({
      name: 'Concurrent API Request Pattern',
      description: 'Code appears to make multiple concurrent API requests, which could be used to bypass rate limiting if not properly implemented on the server.',
      severity: 'Medium',
      location: 'JavaScript Code - Concurrent Requests'
    });
  }
  
  // Check for request retry logic that might bypass rate limiting
  if (scriptContent.match(/retry|retries/i) && 
      scriptContent.match(/catch\s*\(\s*[^)]+\)\s*\{[^}]*(?:fetch|ajax|get|post)/i)) {
    
    // Check if there's proper backoff mechanism
    const hasBackoff = 
      scriptContent.match(/setTimeout\s*\([^,]+,\s*[^)]*\*\s*(?:retryCount|attempts|tries|i)/i) ||
      scriptContent.match(/(?:exponential|backoff)/i);
    
    if (!hasBackoff) {
      vulnerabilities.push({
        name: 'Improper Retry Logic',
        description: 'Request retry logic without proper exponential backoff could be used to bypass rate limiting.',
        severity: 'Medium',
        location: 'JavaScript Code - Retry Logic'
      });
    }
  }
  
  // Check for rotating identifiers (potential sign of trying to bypass rate limits)
  if ((scriptContent.match(/random\(\)|Math\.random\(\)/i) || 
       scriptContent.match(/\(new Date\(\)\)\.getTime\(\)/i) || 
       scriptContent.match(/Date\.now\(\)/i)) && 
      (scriptContent.match(/headers\s*:/i) || scriptContent.match(/setRequestHeader/i))) {
    
    vulnerabilities.push({
      name: 'Potential Identifier Rotation',
      description: 'Code appears to generate random or time-based values for request headers, which might be an attempt to bypass rate limiting or tracking.',
      severity: 'Medium',
      location: 'JavaScript Code - Header Manipulation'
    });
  }
  
  // Check for distributed requests across multiple tabs/windows
  if (scriptContent.match(/localStorage\s*\.\s*setItem\s*\(\s*["'](?:requests|api_calls|counter)["']/i) &&
      scriptContent.match(/\+\+|increment|\+=|>/i)) {
    
    vulnerabilities.push({
      name: 'Cross-Tab Request Coordination',
      description: 'Code appears to track API request counts across browser tabs, which might be used to distribute requests to stay under rate limits.',
      severity: 'Low',
      location: 'JavaScript Code - Request Tracking'
    });
  }
  
  // Check for timing manipulation that could bypass rate limiting
  if (scriptContent.match(/setTimeout\s*\(\s*function\s*\(\s*\)\s*\{[^}]*(?:fetch|ajax|get|post|request)/i) &&
      scriptContent.match(/\+\s*Math\.random\(\)\s*\*/i)) {
    
    vulnerabilities.push({
      name: 'Request Timing Manipulation',
      description: 'Code uses randomized delays between API requests, which could be an attempt to evade detection of automated requests or bypass rate limiting.',
      severity: 'Low',
      location: 'JavaScript Code - Request Timing'
    });
  }
}

// Check for Cross-Site Request Forgery (CSRF) vulnerabilities
function checkCSRFVulnerabilities(vulnerabilities) {
  // Get all forms on the page
  const forms = document.querySelectorAll('form');
  
  // Check each form for CSRF vulnerabilities
  for (const form of forms) {
    const method = form.getAttribute('method') || 'get';
    
    // CSRF is primarily a concern for state-changing operations (POST, PUT, DELETE)
    if (method.toLowerCase() === 'post' || method.toLowerCase() === 'put' || method.toLowerCase() === 'delete') {
      // Look for CSRF tokens in the form
      const inputs = form.querySelectorAll('input[type="hidden"]');
      let hasCSRFToken = false;
      
      for (const input of inputs) {
        const name = input.getAttribute('name') || '';
        const value = input.getAttribute('value') || '';
        
        // Check for common CSRF token naming patterns
        if (name.toLowerCase().includes('csrf') || 
            name.toLowerCase().includes('token') || 
            name.toLowerCase().includes('xsrf') || 
            name.toLowerCase().includes('_token') ||
            name.toLowerCase() === 'authenticity_token') {
          
          hasCSRFToken = true;
          break;
        }
      }
      
      // Flag forms without CSRF tokens
      if (!hasCSRFToken) {
        vulnerabilities.push({
          name: 'Missing CSRF Protection',
          description: 'Form with state-changing operation (POST/PUT/DELETE) does not appear to include a CSRF token, which could make it vulnerable to Cross-Site Request Forgery attacks.',
          severity: 'High',
          location: `Form ${form.id ? 'id="' + form.id + '"' : (form.getAttribute('action') ? 'action="' + form.getAttribute('action') + '"' : '')}`
        });
      }
    }
  }
  
  // Check for CSRF protection in JavaScript-based submissions
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Look for AJAX form submissions
  if ((scriptContent.match(/\.ajax\s*\(\s*\{/i) || 
       scriptContent.match(/\$\.post/i) || 
       scriptContent.match(/fetch\s*\(/i) || 
       scriptContent.match(/new\s+FormData/i)) &&
       scriptContent.match(/method\s*:\s*['"]POST['"]|type\s*:\s*['"]POST['"]/i)) {
    
    // Look for CSRF token inclusion in these requests
    const hasCSRFInRequests = 
      scriptContent.match(/['"]\s*X-CSRF-TOKEN\s*['"]|['"]\s*csrf-token\s*['"]|['"]\s*_token\s*['"]|['"]\s*authenticity_token\s*['"]/i) ||
      scriptContent.match(/headers\s*\[\s*['"]X-CSRF-TOKEN['"]\s*\]|headers\.append\s*\(\s*['"]X-CSRF-TOKEN['"]/i) ||
      scriptContent.match(/formData\.append\s*\(\s*['"]_token['"]/i);
    
    if (!hasCSRFInRequests) {
      vulnerabilities.push({
        name: 'Missing CSRF Protection in AJAX Requests',
        description: 'JavaScript-based form submissions do not appear to include CSRF tokens, which could make them vulnerable to Cross-Site Request Forgery attacks.',
        severity: 'High',
        location: 'JavaScript Code - AJAX Requests'
      });
    }
  }
  
  // Check for Same-Site cookie attribute in HTTP-only environments
  // (can't check HTTP headers directly in content script, but can check meta tags that might set cookies)
  const metaCookies = document.querySelectorAll('meta[http-equiv="Set-Cookie"]');
  for (const meta of metaCookies) {
    const content = meta.getAttribute('content') || '';
    if (content.includes('session') || content.includes('auth') || content.includes('token')) {
      if (!content.includes('SameSite=Strict') && !content.includes('SameSite=Lax')) {
        vulnerabilities.push({
          name: 'Missing SameSite Cookie Attribute',
          description: 'Cookies set via meta tags do not use the SameSite attribute, which helps prevent CSRF attacks.',
          severity: 'Medium',
          location: 'Meta Tag Set-Cookie'
        });
        break;
      }
    }
  }
}

// Check for weak CSRF token implementation
function checkWeakCSRFTokens(vulnerabilities) {
  // Get all forms on the page
  const forms = document.querySelectorAll('form');
  
  // Check each form for weak CSRF token patterns
  for (const form of forms) {
    const inputs = form.querySelectorAll('input[type="hidden"]');
    
    for (const input of inputs) {
      const name = input.getAttribute('name') || '';
      const value = input.getAttribute('value') || '';
      
      // Check if this is a CSRF token input
      if (name.toLowerCase().includes('csrf') || 
          name.toLowerCase().includes('token') || 
          name.toLowerCase().includes('xsrf') || 
          name === '_token' ||
          name === 'authenticity_token') {
        
        // Check for potentially weak token patterns
        if (value.length < 16) {
          // Too short to be secure
          vulnerabilities.push({
            name: 'Weak CSRF Token - Insufficient Length',
            description: 'CSRF token is too short to provide adequate security. Tokens should be at least 16 characters long with high entropy.',
            severity: 'High',
            location: `Form input: ${name}="${value}"`
          });
        } else if (/^[0-9]+$/.test(value)) {
          // All numeric - likely a timestamp or sequential number
          vulnerabilities.push({
            name: 'Weak CSRF Token - All Numeric',
            description: 'CSRF token appears to be all numeric, suggesting it might be a timestamp or sequential number, which is predictable.',
            severity: 'High',
            location: `Form input: ${name}="${value}"`
          });
        } else if (/^[a-zA-Z0-9]{32}$/.test(value) && value.toUpperCase() === value) {
          // Possibly an MD5 hash
          vulnerabilities.push({
            name: 'Potential Weak CSRF Token - Hash Function',
            description: 'CSRF token appears to be a 32-character hexadecimal string, suggesting it might be an MD5 hash, which is not cryptographically secure.',
            severity: 'Medium',
            location: `Form input: ${name}="${value}"`
          });
        }
      }
    }
  }
  
  // Check for CSRF token extraction or generation in JavaScript
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for weak token generation patterns
  if (scriptContent.match(/['"]csrf['"]|['"]_token['"]|['"]csrf_token['"]/i)) {
    // Check for use of timestamp as token
    if (scriptContent.match(/new\s+Date\s*\(\s*\)\.getTime\s*\(\s*\)|Date\.now\s*\(\s*\)/i) &&
        scriptContent.match(/token\s*=|csrf\s*=|_token\s*=/i)) {
      
      vulnerabilities.push({
        name: 'Weak CSRF Token Generation - Timestamp',
        description: 'CSRF token appears to be generated using a timestamp, which is predictable and insecure.',
        severity: 'High',
        location: 'JavaScript Code - Token Generation'
      });
    }
    
    // Check for use of Math.random() for token generation
    if (scriptContent.match(/Math\.random\s*\(\s*\)/i) &&
        scriptContent.match(/token\s*=|csrf\s*=|_token\s*=/i)) {
      
      vulnerabilities.push({
        name: 'Weak CSRF Token Generation - Math.random()',
        description: 'CSRF token appears to be generated using Math.random(), which is not cryptographically secure and can be predicted.',
        severity: 'High',
        location: 'JavaScript Code - Token Generation'
      });
    }
    
    // Check for reuse of tokens from DOM
    if (scriptContent.match(/document\.getElementsByName\s*\(\s*['"]csrf_token['"]|document\.querySelector\s*\(\s*['"]input\[name=["']csrf_token["']\]['"]/i) &&
        scriptContent.match(/localStorage|sessionStorage|cookie/i)) {
      
      vulnerabilities.push({
        name: 'Potential CSRF Token Reuse',
        description: 'Code appears to store CSRF tokens in client storage, which could lead to token reuse across requests and sessions.',
        severity: 'Medium',
        location: 'JavaScript Code - Token Storage'
      });
    }
  }
}

// Check for improper request validation
function checkImproperRequestValidation(vulnerabilities) {
  // Get all scripts on the page
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for form submissions without validation
  if ((scriptContent.match(/\.submit\s*\(\s*\)/i) || 
       scriptContent.match(/document\.forms/i)) &&
      !scriptContent.match(/validate|validation|validator|isValid|checkValid/i)) {
    
    vulnerabilities.push({
      name: 'Form Submission Without Validation',
      description: 'JavaScript code appears to submit forms without validating input, which could lead to injection attacks or data integrity issues.',
      severity: 'Medium',
      location: 'JavaScript Code - Form Submission'
    });
  }
  
  // Check for lack of Content-Type validation in AJAX requests
  if (scriptContent.match(/\.ajax\s*\(|\.post\s*\(|\.get\s*\(|fetch\s*\(/i) &&
      scriptContent.match(/JSON\.parse|response\.json\s*\(\s*\)/i) &&
      !scriptContent.match(/Content-Type|content-type|contentType/i)) {
    
    vulnerabilities.push({
      name: 'Missing Content-Type Validation',
      description: 'Code parses JSON responses but does not appear to validate the Content-Type header, which could lead to JSON hijacking attacks.',
      severity: 'Medium',
      location: 'JavaScript Code - AJAX Requests'
    });
  }
  
  // Check for weak Origin/Referer validation
  if (scriptContent.match(/document\.referrer|headers\s*\[\s*['"]Referer['"]|headers\s*\[\s*['"]Origin['"]/i) &&
      !scriptContent.match(/===\s*['"]https:\/\/|\.indexOf\s*\(\s*['"]https:\/\/[^'"]+['"]\s*\)\s*===\s*0/i)) {
    
    vulnerabilities.push({
      name: 'Weak Referer/Origin Validation',
      description: 'Code appears to check Referer or Origin headers but may not properly validate the full URL, which could allow request forgery from similar domains.',
      severity: 'Medium',
      location: 'JavaScript Code - Request Validation'
    });
  }
  
  // Check for weak redirect validation
  if ((scriptContent.match(/location\s*=|location\.href\s*=|window\.location\s*=|location\.replace/i) &&
       scriptContent.match(/\.value|getElementById|querySelector/i) &&
       !scriptContent.match(/validate|sanitize|check/i)) ||
      (scriptContent.match(/\.open\s*\(\s*['"]GET['"],/i) && 
       scriptContent.match(/\+\s*.*?\.value/i))) {
    
    vulnerabilities.push({
      name: 'Unvalidated Redirect',
      description: 'Code performs redirects using unvalidated input values, which could lead to open redirect vulnerabilities.',
      severity: 'Medium',
      location: 'JavaScript Code - Redirects'
    });
  }
  
  // Check for insufficient URL validation
  if (scriptContent.match(/new\s+URL\s*\(|URL\.createObjectURL/i) &&
      scriptContent.match(/\.value|getElementById|querySelector/i) &&
      !scriptContent.match(/validate|sanitize|check/i)) {
    
    vulnerabilities.push({
      name: 'Insufficient URL Validation',
      description: 'Code creates URLs from user input without proper validation, which could lead to security vulnerabilities.',
      severity: 'Medium',
      location: 'JavaScript Code - URL Handling'
    });
  }
  
  // Check forms with file uploads for proper validation
  const formWithFileUploads = document.querySelectorAll('form[enctype="multipart/form-data"]');
  for (const form of formWithFileUploads) {
    const fileInputs = form.querySelectorAll('input[type="file"]');
    if (fileInputs.length > 0) {
      // Check for file validation in associated JavaScript
      let hasFileValidation = false;
      
      // Try to find script related to this form by ID
      const formId = form.getAttribute('id');
      if (formId && scriptContent.includes(formId)) {
        hasFileValidation = scriptContent.match(new RegExp(`${formId}.*?(file|size|type).*?(validate|check|verify)`, 'i')) !== null;
      }
      
      // Check for general file validation patterns if form id-specific check didn't find anything
      if (!hasFileValidation) {
        for (const input of fileInputs) {
          const inputId = input.getAttribute('id');
          const inputName = input.getAttribute('name');
          
          if ((inputId && scriptContent.includes(inputId)) || (inputName && scriptContent.includes(inputName))) {
            hasFileValidation = 
              scriptContent.match(/\.type|\.size|\.extension|\.name/i) && 
              scriptContent.match(/if\s*\(|validate|check|verify/i);
            
            if (hasFileValidation) break;
          }
        }
      }
      
      if (!hasFileValidation) {
        vulnerabilities.push({
          name: 'Improper File Upload Validation',
          description: 'Form includes file uploads but no client-side validation of file type, size, or content was detected.',
          severity: 'Medium',
          location: `Form ${formId ? 'id="' + formId + '"' : 'with file upload'}`
        });
      }
    }
  }
}

// Scan JavaScript source code for security patterns
function scanJavaScriptSourceCode(vulnerabilities) {
  // Collect all JavaScript code from inline scripts and external scripts where possible
  const scripts = document.querySelectorAll('script');
  let inlineScriptContent = '';
  const externalScriptUrls = [];
  
  // Collect inline scripts and URLs of external scripts
  for (const script of scripts) {
    if (!script.src) {
      inlineScriptContent += script.textContent + '\n';
    } else if (script.src) {
      externalScriptUrls.push(script.src);
    }
  }
  
  // Analyze inline script content
  analyzeJavaScriptCode(inlineScriptContent, 'Inline Scripts', vulnerabilities);
  
  // Report external scripts (we can't analyze their content directly,
  // but we can note their existence and potentially check if they're from untrusted sources)
  for (const url of externalScriptUrls) {
    if (!url.startsWith('https:')) {
      vulnerabilities.push({
        name: 'Insecure External Script',
        description: 'External JavaScript loaded over insecure HTTP connection.',
        severity: 'High',
        location: `Script src: ${url}`
      });
    }
    
    // Check for scripts from CDNs without integrity checks
    if (url.includes('cdn.') || url.includes('.jsdelivr.net') || url.includes('.unpkg.com')) {
      const scriptElement = document.querySelector(`script[src="${url}"]`);
      if (!scriptElement.hasAttribute('integrity') || !scriptElement.hasAttribute('crossorigin')) {
        vulnerabilities.push({
          name: 'Missing Subresource Integrity',
          description: 'External script from CDN lacks integrity and/or crossorigin attributes, which verify the script hasn\'t been tampered with.',
          severity: 'Medium',
          location: `Script src: ${url}`
        });
      }
    }
  }
}

// Analyze JavaScript code for security patterns
function analyzeJavaScriptCode(code, location, vulnerabilities) {
  // Skip if there's no code to analyze
  if (!code || code.trim() === '') return;
  
  // Security pattern checks that aren't covered by other specific checks
  
  // Check for use of dangerous JavaScript features
  checkDangerousJSFeatures(code, location, vulnerabilities);
  
  // Check for insecure crypto usage
  checkInsecureCrypto(code, location, vulnerabilities);
  
  // Check for debugger statements and console logs in production
  checkDebuggerStatements(code, location, vulnerabilities);
  
  // Check for timing attacks vulnerability patterns
  checkTimingAttacks(code, location, vulnerabilities);
  
  // Check for client-side business logic implementation
  checkClientSideBusinessLogic(code, location, vulnerabilities);
  
  // Check for insecure randomness
  checkInsecureRandomness(code, location, vulnerabilities);
  
  // Check for regex denial of service (additional patterns not covered in checkReDoS)
  checkExtendedReDoS(code, location, vulnerabilities);
  
  // Check for insecure data serialization
  checkInsecureSerialization(code, location, vulnerabilities);
  
  // Check for postMessage vulnerabilities
  checkPostMessageVulnerabilities(code, location, vulnerabilities);
  
  // Check for DOM clobbering defense
  checkDOMClobberingDefense(code, location, vulnerabilities);
  
  // Check for browser fingerprinting techniques
  checkBrowserFingerprinting(code, location, vulnerabilities);
}

// Check for dangerous JavaScript features
function checkDangerousJSFeatures(code, location, vulnerabilities) {
  // Check for use of with statement (can lead to confusion and vulnerabilities)
  if (/\bwith\s*\(/i.test(code)) {
    vulnerabilities.push({
      name: 'Use of Dangerous JavaScript Feature: with Statement',
      description: 'The with statement is deprecated and can lead to variable scope confusion and potential security issues.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for Function constructor (similar to eval)
  if (/new\s+Function\s*\(/i.test(code)) {
    vulnerabilities.push({
      name: 'Use of Function Constructor',
      description: 'The Function constructor is similar to eval() and can execute arbitrary code, posing security risks.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for iframe srcdoc
  if (/\.srcdoc\s*=|srcdoc\s*=/i.test(code)) {
    vulnerabilities.push({
      name: 'Dynamic iFrame srcdoc Manipulation',
      description: 'Code dynamically sets iframe srcdoc content, which could lead to XSS if the content is derived from user input.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for dangerous property access patterns
  if (/\[\s*['"](?:__proto__|constructor|prototype|__defineGetter__|__defineSetter__)['"]\s*\]/i.test(code)) {
    vulnerabilities.push({
      name: 'Access to Dangerous Object Properties',
      description: 'Code accesses JavaScript object properties that are commonly used in prototype pollution or privilege escalation attacks.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for iframe sandboxing bypass
  if (/\.sandbox\s*=\s*['"]\s*allow-scripts\s*allow-same-origin/i.test(code)) {
    vulnerabilities.push({
      name: 'Insecure iFrame Sandbox Configuration',
      description: 'iFrame sandbox attributes allow both scripts and same-origin, which essentially defeats the purpose of sandboxing.',
      severity: 'Medium',
      location: location
    });
  }
}

// Check for insecure crypto usage
function checkInsecureCrypto(code, location, vulnerabilities) {
  // Check for weak crypto algorithms
  if (/MD5|SHA-?1|DES|RC4/i.test(code)) {
    vulnerabilities.push({
      name: 'Usage of Weak Cryptographic Algorithms',
      description: 'Weak or outdated cryptographic algorithms detected. These algorithms are no longer considered secure.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for client-side encryption without server verification
  if (/(encrypt|cipher|AES)/i.test(code) && !/(verify|validate|sign)/i.test(code)) {
    vulnerabilities.push({
      name: 'Client-Side Encryption Without Verification',
      description: 'Client-side encryption is being used without apparent server-side verification, which may give a false sense of security.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for use of insecure crypto libraries
  if (/\.?CryptoJS\.(?!SHA256|SHA384|SHA512|SHA3|PBKDF2|AES)/i.test(code)) {
    vulnerabilities.push({
      name: 'Potential Use of Insecure Crypto Methods',
      description: 'Usage of CryptoJS without specifying a strong algorithm could result in insecure cryptographic operations.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for custom crypto implementations
  if (/function\s+(?:encrypt|decrypt|hash|cipher|encode)/i.test(code)) {
    vulnerabilities.push({
      name: 'Custom Cryptographic Implementation',
      description: 'Custom implementation of cryptographic functions detected. Using custom crypto instead of vetted libraries is generally risky.',
      severity: 'Medium',
      location: location
    });
  }
}

// Check for debugger statements and console logs
function checkDebuggerStatements(code, location, vulnerabilities) {
  // Check for debugger statements
  if (/\bdebugger\b/i.test(code)) {
    vulnerabilities.push({
      name: 'Debugger Statement in Code',
      description: 'Debugger statements in production code can allow an attacker to pause execution and inspect variables.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for excessive console logging that might leak sensitive data
  if (/console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:password|token|key|secret|auth|account)/i.test(code)) {
    vulnerabilities.push({
      name: 'Sensitive Data in Console Logs',
      description: 'Console logging statements may contain sensitive information, which could be exposed in browser developer tools.',
      severity: 'Medium',
      location: location
    });
  }
}

// Check for code patterns vulnerable to timing attacks
function checkTimingAttacks(code, location, vulnerabilities) {
  // Check for simple string comparison for sensitive data
  if (/===\s*['"][^'"]*['"]\s*\|\|\s*password|password\s*===\s*['"][^'"]*['"]/i.test(code)) {
    vulnerabilities.push({
      name: 'Potential Timing Attack Vulnerability',
      description: 'Simple string comparisons for passwords or tokens may be vulnerable to timing attacks. Use constant-time comparison functions instead.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for timing-based user enumeration
  if (/user.*not.*found|username.*invalid/i.test(code) && /getElementById\(.*?message/i.test(code)) {
    vulnerabilities.push({
      name: 'User Enumeration Vulnerability',
      description: 'Different error messages for invalid users versus invalid passwords can enable user enumeration attacks.',
      severity: 'Medium',
      location: location
    });
  }
}

// Check for client-side business logic implementation
function checkClientSideBusinessLogic(code, location, vulnerabilities) {
  // Check for client-side price calculation
  if (/(?:price|cost|total)\s*=|calculate(?:Price|Total|Cost)/i.test(code) && 
      /\.value|getElementById|querySelector.*\.value/i.test(code)) {
    
    vulnerabilities.push({
      name: 'Client-Side Price Calculation',
      description: 'Price calculations appear to be performed on the client side, which could be manipulated by users. Always verify prices on the server.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for client-side discount validation
  if (/(?:discount|coupon|promo)\s*Code/i.test(code) && 
      /if\s*\(|switch\s*\(/i.test(code) && 
      !/ajax|fetch|\.post|\.get/i.test(code)) {
    
    vulnerabilities.push({
      name: 'Client-Side Discount Validation',
      description: 'Discount or promo codes appear to be validated on the client side, which could be bypassed. Always verify on the server.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for client-side role/permission checks
  if (/(?:isAdmin|hasRole|can(?:Edit|Delete|Create|Update)|permissions|role\s*==)/i.test(code) &&
      !/(?:fetch|ajax|get|post).*\.then.*role/i.test(code)) {
    
    vulnerabilities.push({
      name: 'Client-Side Permission Checks',
      description: 'User roles or permissions appear to be checked on the client side, which could be bypassed. Always verify permissions on the server.',
      severity: 'Critical',
      location: location
    });
  }
}

// Check for insecure randomness
function checkInsecureRandomness(code, location, vulnerabilities) {
  // Check for Math.random() used for security purposes
  if (/Math\.random\s*\(\s*\)/i.test(code) && 
      /(?:token|password|key|secure|random(?:Id|String|Bytes)|uuid)/i.test(code)) {
    
    vulnerabilities.push({
      name: 'Insecure Randomness Source',
      description: 'Math.random() is being used in a security context, but it\'s not cryptographically secure. Use crypto.getRandomValues() instead.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for timestamp used as a randomness source
  if (/(new\s+Date|Date\.now)\s*\(\s*\).*\+\s*Math\.random/i.test(code) && 
      /(?:token|password|key|secure|random(?:Id|String|Bytes)|uuid)/i.test(code)) {
    
    vulnerabilities.push({
      name: 'Timestamp as Randomness Source',
      description: 'Using timestamp with Math.random() is still not cryptographically secure and may be predictable.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for secure randomness implementation
  if (!/crypto\.getRandomValues|webcrypto|SubtleCrypto/i.test(code) && 
      /(?:generate|create).*(?:Token|Password|Key|Secret)/i.test(code)) {
    
    vulnerabilities.push({
      name: 'Missing Secure Random Number Generator',
      description: 'Code appears to generate security-sensitive values without using a cryptographically secure random number generator.',
      severity: 'Medium',
      location: location
    });
  }
}

// Check for extended ReDoS patterns
function checkExtendedReDoS(code, location, vulnerabilities) {
  // These are additional patterns beyond what's checked in the main ReDoS function
  
  // Check for use of greedy quantifiers with alternation in regex
  if (/new\s+RegExp\s*\(\s*['"][^'"]*\.\*.*\|.*\.\*[^'"]*['"]/i.test(code) || 
      /\/[^\/]*\.\*.*\|.*\.\*[^\/]*\//i.test(code)) {
    
    vulnerabilities.push({
      name: 'ReDoS Vulnerable Regex Pattern',
      description: 'Regular expression uses greedy quantifiers with alternation, which can cause catastrophic backtracking and lead to DoS.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for nested repetition quantifiers
  if (/new\s+RegExp\s*\(\s*['"][^'"]*\(.*[\+\*\{\d,\}].*\)[\+\*\{\d,\}][^'"]*['"]/i.test(code) || 
      /\/[^\/]*\(.*[\+\*\{\d,\}].*\)[\+\*\{\d,\}][^\/]*\//i.test(code)) {
    
    vulnerabilities.push({
      name: 'ReDoS Vulnerable Nested Quantifiers',
      description: 'Regular expression uses nested repetition quantifiers, which can cause exponential backtracking and lead to DoS.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for use of regexes with user input without timeouts
  if ((code.match(/new\s+RegExp\s*\([^)]*(?:value|input|param)/i) || 
       code.match(/\.match\s*\([^)]*(?:value|input|param)/i)) && 
      !code.match(/setTimeout|timeout/i)) {
    
    vulnerabilities.push({
      name: 'Uncontrolled Regex with User Input',
      description: 'Regular expressions constructed from user input without timeout mechanisms could lead to ReDoS attacks.',
      severity: 'Medium',
      location: location
    });
  }
}

// Check for insecure data serialization
function checkInsecureSerialization(code, location, vulnerabilities) {
  // Check for eval with JSON.parse alternative
  if (/eval\s*\(\s*['"].*?\s*\+/i.test(code) && !code.includes('JSON.parse')) {
    vulnerabilities.push({
      name: 'Insecure Data Deserialization',
      description: 'Code appears to use eval() for data deserialization instead of JSON.parse(), which is a security risk.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for unvalidated JSON parsing
  if (/JSON\.parse\s*\(/i.test(code) && !code.match(/try\s*\{.*?JSON\.parse/i)) {
    vulnerabilities.push({
      name: 'Unhandled JSON Parsing',
      description: 'JSON.parse() is used without a try/catch block, which could cause application crashes with malformed input.',
      severity: 'Low',
      location: location
    });
  }
  
  // Check for potentially unsafe object deserialization methods
  if (/fromJSON|deserialize|unserialize/i.test(code)) {
    vulnerabilities.push({
      name: 'Potential Unsafe Deserialization',
      description: 'Custom deserialization methods detected. Ensure these methods validate and sanitize input properly.',
      severity: 'Medium',
      location: location
    });
  }
}

// Check for postMessage vulnerabilities
function checkPostMessageVulnerabilities(code, location, vulnerabilities) {
  // Check for postMessage without origin checks
  if (/\.postMessage\s*\(/i.test(code) && !code.match(/targetOrigin\s*:\s*['"][^*][^'"]*['"]/i)) {
    vulnerabilities.push({
      name: 'Insecure postMessage Usage',
      description: 'postMessage is used without specifying a concrete targetOrigin, which could allow sending data to any domain.',
      severity: 'High',
      location: location
    });
  }
  
  // Check for message event listeners without origin validation
  if (/addEventListener\s*\(\s*['"]message['"]/i.test(code) && 
      !code.match(/e\.origin\s*===|event\.origin\s*===|\borigin\b.*?\s*===\s*['"]http/i)) {
    
    vulnerabilities.push({
      name: 'Missing Origin Check in message Event',
      description: 'Event listener for "message" events does not validate the origin of the sender, which could allow cross-origin attacks.',
      severity: 'High',
      location: location
    });
  }
}

// Check for DOM clobbering defense
function checkDOMClobberingDefense(code, location, vulnerabilities) {
  // Check for direct access to DOM properties without hasOwnProperty checks
  if (code.match(/\.(id|name|nodeName)\s*===|===/i) && 
      !code.match(/hasOwnProperty|Object\.prototype\.hasOwnProperty|instanceof\s+HTML/i)) {
    
    vulnerabilities.push({
      name: 'Potential DOM Clobbering Vulnerability',
      description: 'Code accesses DOM properties without checking if they are actual properties rather than DOM elements, which could lead to DOM clobbering attacks.',
      severity: 'Medium',
      location: location
    });
  }
  
  // Check for direct property access that could be clobbered
  if (code.match(/\bconfig\s*\.\s*\w+|\bsettings\s*\.\s*\w+|\boptions\s*\.\s*\w+/i) && 
      !code.match(/Object\.create\s*\(null\)/i)) {
    
    vulnerabilities.push({
      name: 'Potential Object Property Clobbering',
      description: 'Direct access to object properties without protection against prototype pollution or DOM clobbering detected.',
      severity: 'Low',
      location: location
    });
  }
}

// Check for browser fingerprinting techniques
function checkBrowserFingerprinting(code, location, vulnerabilities) {
  // Count fingerprinting techniques used
  let fingerprintingTechniques = 0;
  
  // Check for canvas fingerprinting
  if (/canvas[^\.]*\.toDataURL|getImageData/i.test(code)) {
    fingerprintingTechniques++;
  }
  
  // Check for font enumeration
  if (/document\.fonts|FontFace|font-family.*?serif|font-family.*?sans/i.test(code)) {
    fingerprintingTechniques++;
  }
  
  // Check for WebRTC IP detection
  if (/RTCPeerConnection|createDataChannel|onicecandidate/i.test(code)) {
    fingerprintingTechniques++;
  }
  
  // Check for navigator property collection
  if (/navigator\.(?:userAgent|platform|language|languages|buildID|hardwareConcurrency|deviceMemory)/i.test(code)) {
    fingerprintingTechniques++;
  }
  
  // Check for audio fingerprinting
  if (/AudioContext|OfflineAudioContext|createOscillator|createAnalyser/i.test(code)) {
    fingerprintingTechniques++;
  }
  
  // Report if multiple fingerprinting techniques are found
  if (fingerprintingTechniques >= 3) {
    vulnerabilities.push({
      name: 'Browser Fingerprinting Detected',
      description: 'Multiple browser fingerprinting techniques detected. While not inherently malicious, fingerprinting raises privacy concerns and may violate regulations like GDPR.',
      severity: 'Medium',
      location: location
    });
  }
} 