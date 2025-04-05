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
  
  // Check for XSS vulnerabilities (new)
  checkForXSSVulnerabilities(vulnerabilities);
  
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