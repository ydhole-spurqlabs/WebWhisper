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