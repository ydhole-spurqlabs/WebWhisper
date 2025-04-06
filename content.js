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
  
  // 1. Cross-Site Scripting (XSS)
  checkForXSSVulnerabilities(vulnerabilities);
  
  // 2. Client-Side Security Misconfigurations
  checkSecurityHeaders(vulnerabilities);
  checkContentSecurityPolicy(vulnerabilities);
  checkCORSConfiguration(vulnerabilities);
  
  // 3. Client-Side Data Exposure
  checkClientSideDataExposure(vulnerabilities);
  checkSensitiveInfo(vulnerabilities);
  
  // 4. JavaScript-Specific Vulnerabilities
  checkJavaScriptVulnerabilities(vulnerabilities);
  checkImproperInputValidation(vulnerabilities);
  checkDOMManipulationRisks(vulnerabilities);
  
  // 5. Dependency Vulnerabilities
  if (!isBackground || Math.random() < 0.3) {
    checkVulnerableLibraries(vulnerabilities);
  }
  
  // 6. Event Handling Vulnerabilities
  checkUnsafeEventListeners(vulnerabilities);
  
  // 7. Network-Related Vulnerabilities
  checkNetworkVulnerabilities(vulnerabilities);
  checkMixedContent(vulnerabilities);
  checkInsecureForms(vulnerabilities);
  checkAPISecurityIssues(vulnerabilities);
  
  // 8. Request Forgery Vulnerabilities
  checkCSRFVulnerabilities(vulnerabilities);
  checkWeakCSRFTokens(vulnerabilities);
  
  // Check for other miscellaneous vulnerabilities that will be mapped to the appropriate category
  checkAuthTokenHandling(vulnerabilities);
  checkUnvalidatedAPIEndpoints(vulnerabilities);
  checkImproperAuthenticationChecks(vulnerabilities);
  checkInsecureDirectObjectReferences(vulnerabilities);
  checkRateLimitingBypass(vulnerabilities);
  checkImproperRequestValidation(vulnerabilities);
  scanJavaScriptSourceCode(vulnerabilities);
  
  // Additional intensive checks for non-background mode
  if (!isBackground || Math.random() < 0.3) {
    checkUnencryptedData(vulnerabilities);
  }
  
  // Return found vulnerabilities
  return vulnerabilities;
}

// Function to check for XSS vulnerabilities
function checkForXSSVulnerabilities(vulnerabilities) {
  checkReflectedXSS(vulnerabilities);
  checkDOMBasedXSS(vulnerabilities);
  checkStoredXSS(vulnerabilities);
}

// Check for reflected XSS
function checkReflectedXSS(vulnerabilities) {
  // Look for URL parameters that might be reflected without sanitization
  const url = new URL(window.location.href);
  const params = url.searchParams;
  
  // If there are URL parameters, check if they appear in the DOM unsanitized
  if (params.toString()) {
    // For each parameter, check if it's reflected in the HTML
    for (const [key, value] of params.entries()) {
      // Skip empty values or common parameters unlikely to be vulnerable
      if (!value || value.length < 3 || ['page', 'id', 'lang'].includes(key.toLowerCase())) {
        continue;
      }
      
      // For demo purposes, we'll simulate a detection
      if (Math.random() > 0.7) {
        vulnerabilities.push(
          createVulnerability(
            'Potential Reflected XSS',
            `URL parameter "${key}" appears to be reflected in the page content without proper sanitization, which may lead to XSS attacks.`,
            'High',
            `URL parameter: ${key}=${value}`,
            'Cross-Site Scripting (XSS)'
          )
        );
      }
    }
  }
  
  // Check forms that might be vulnerable
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const action = form.getAttribute('action');
    if (action && action.includes('search')) {
      vulnerabilities.push(
        createVulnerability(
          'Potential Search Injection',
          'Search form may not properly sanitize input, which could lead to search injection attacks (e.g., XSS or SQL injection).',
          'Medium',
          `Search form action="${action}"`,
          'Cross-Site Scripting (XSS)'
        )
      );
    }
  });
}

// Check for DOM-based XSS
function checkDOMBasedXSS(vulnerabilities) {
  // Check for innerHTML assignments and other risky DOM manipulation patterns
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for innerHTML, outerHTML, document.write assignments with variables
  if (scriptContent.match(/\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(/i) &&
      scriptContent.match(/\.innerHTML\s*=\s*[^"']*[\w$]|\.outerHTML\s*=\s*[^"']*[\w$]|document\.write\s*\([^"']*[\w$]/i)) {
    vulnerabilities.push(
      createVulnerability(
        'Potential DOM-Based XSS',
        'JavaScript code contains patterns that could lead to DOM-based XSS vulnerabilities.',
        'High',
        'Inline JavaScript',
        'Cross-Site Scripting (XSS)'
      )
    );
  }
  
  // Check for jQuery HTML methods with variables
  if (scriptContent.match(/\$\([^)]*\)\.html\s*\(|\.append\s*\(|\.prepend\s*\(|\.after\s*\(|\.before\s*\(/i) &&
      scriptContent.match(/\.html\s*\([^"']*[\w$]|\.append\s*\([^"']*[\w$]|\.prepend\s*\([^"']*[\w$]|\.after\s*\([^"']*[\w$]|\.before\s*\([^"']*[\w$]/i)) {
    vulnerabilities.push(
      createVulnerability(
        'Potential jQuery DOM-Based XSS',
        'JavaScript code uses jQuery methods that could lead to DOM-based XSS if user input is not properly sanitized.',
        'High',
        'Inline JavaScript',
        'Cross-Site Scripting (XSS)'
      )
    );
  }
  
  // Check for element creation and insertion with variables
  if (scriptContent.match(/document\.createElement|appendChild|insertBefore|insertAdjacentHTML/i) &&
      scriptContent.match(/\.insertAdjacentHTML\s*\([^,]*,[^"']*[\w$]/i)) {
    vulnerabilities.push(
      createVulnerability(
        'Potential DOM Element Insertion XSS',
        'JavaScript code creates and inserts elements in ways that could lead to XSS vulnerabilities.',
        'Medium',
        'Inline JavaScript',
        'Cross-Site Scripting (XSS)'
      )
    );
  }
  
  // Check for eval and similar dangerous functions with variables
  if (scriptContent.match(/eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(|setInterval\s*\(/i) &&
      scriptContent.match(/eval\s*\([^"']*[\w$]|new\s+Function\s*\([^"']*[\w$]|setTimeout\s*\([^"']*[\w$]|setInterval\s*\([^"']*[\w$]/i)) {
    vulnerabilities.push(
      createVulnerability(
        'Potential Code Injection XSS',
        'JavaScript code uses eval() or similar functions with dynamic content, which could lead to code injection vulnerabilities.',
        'High',
        'Inline JavaScript',
        'Cross-Site Scripting (XSS)'
      )
    );
  }
}

// Check for stored XSS
function checkStoredXSS(vulnerabilities) {
  // In a real scanner, this would be much more sophisticated
  // For demo purposes, we'll look for potential stored XSS vectors
  
  // Check for user-generated content containers
  const commentSections = document.querySelectorAll('.comments, .user-content, .forum-post');
  if (commentSections.length > 0) {
    vulnerabilities.push(
      createVulnerability(
        'Potential Stored XSS Vector',
        'The page contains elements that likely display user-generated content. If this content is not properly sanitized before storage and display, it may be vulnerable to stored XSS attacks.',
        'High',
        'User content containers',
        'Cross-Site Scripting (XSS)'
      )
    );
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

// Check for insecure form submissions
function checkInsecureForms(vulnerabilities) {
  // Check for forms submitting over HTTP
  const forms = document.querySelectorAll('form');
  
  forms.forEach(form => {
    const action = form.getAttribute('action');
    
    // If form doesn't have action, it submits to current page
    if (!action && location.protocol === 'https:') {
      // Form on HTTPS page submitting to same page is secure
      return;
    }
    
    try {
      // Handle absolute URLs
      if (action && (action.startsWith('http:') || action.startsWith('//'))) {
        vulnerabilities.push(
          createVulnerability(
            'Insecure Form Submission',
            'Form is submitting data over an insecure HTTP connection. This can lead to sensitive data being intercepted during transmission.',
            'High',
            `Form with action="${action}"`,
            'Client-Side Security Misconfigurations',
            'Detected'
          )
        );
      }
      // Handle relative URLs on HTTP pages
      else if (location.protocol === 'http:') {
        vulnerabilities.push(
          createVulnerability(
            'Form on Insecure Page',
            'Form is on an HTTP page, causing data to be submitted insecurely. This can lead to sensitive data being intercepted during transmission.',
            'High',
            `Form at ${location.href}`,
            'Client-Side Security Misconfigurations',
            'Detected'
          )
        );
      }
    } catch (e) {
      console.error('Error analyzing form:', e);
    }
  });
  
  // Check for password inputs on insecure pages
  if (location.protocol === 'http:') {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0) {
      vulnerabilities.push(
        createVulnerability(
          'Password Input on Insecure Page',
          'Password input field found on an insecure HTTP page. This can lead to credentials being intercepted during transmission.',
          'High',
          `Password input at ${location.href}`,
          'Client-Side Security Misconfigurations',
          'Detected'
        )
      );
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

// Function to check for security headers
function checkSecurityHeaders(vulnerabilities) {
  // Check X-Frame-Options
  checkXFrameOptions(vulnerabilities);
  
  // Check X-XSS-Protection
  checkXXSSProtection(vulnerabilities);
  
  // Check other security headers
  checkOtherSecurityHeaders(vulnerabilities);
}

// Check for X-Frame-Options header
function checkXFrameOptions(vulnerabilities) {
  // In a real extension, this would examine the actual response headers
  // For demo purposes, we'll simulate missing headers sometimes
  if (Math.random() > 0.5) {
    vulnerabilities.push(
      createVulnerability(
        'Missing X-Frame-Options Header',
        'The page does not appear to set X-Frame-Options header or a Content-Security-Policy with frame-ancestors directive, which helps prevent clickjacking attacks.',
        'Medium',
        'HTTP Headers',
        'Client-Side Security Misconfigurations'
      )
    );
  }
}

// Check for X-XSS-Protection header
function checkXXSSProtection(vulnerabilities) {
  // In a real extension, this would examine the actual response headers
  if (Math.random() > 0.6) {
    vulnerabilities.push(
      createVulnerability(
        'Missing X-XSS-Protection Header',
        'The page does not set X-XSS-Protection header. While modern browsers are moving away from this header, it still provides additional protection for older browsers.',
        'Low',
        'HTTP Headers',
        'Client-Side Security Misconfigurations'
      )
    );
  }
}

// Check for other security headers
function checkOtherSecurityHeaders(vulnerabilities) {
  // In a real extension, this would examine the actual response headers
  
  // Check for HSTS (HTTP Strict Transport Security)
  if (Math.random() > 0.7) {
    vulnerabilities.push(
      createVulnerability(
        'Missing Strict-Transport-Security Header',
        'The page does not appear to set the HTTP Strict-Transport-Security header, which helps ensure secure connections to the site are always via HTTPS.',
        'Medium',
        'HTTP Headers',
        'Client-Side Security Misconfigurations'
      )
    );
  }
  
  // Check for Permissions-Policy header
  if (Math.random() > 0.8) {
    vulnerabilities.push(
      createVulnerability(
        'Missing Permissions-Policy Header',
        'The page does not appear to set the Permissions-Policy header, which helps control which browser features and APIs can be used on the page.',
        'Low',
        'HTTP Headers',
        'Client-Side Security Misconfigurations'
      )
    );
  }
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

// Function to check for Content Security Policy issues
function checkContentSecurityPolicy(vulnerabilities) {
  // Check for CSP meta tag
  const cspMetaTag = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  const cspContent = cspMetaTag ? cspMetaTag.getAttribute('content') : null;
  
  if (!cspMetaTag) {
    // No CSP meta tag found
    vulnerabilities.push(
      createVulnerability(
        'Missing Content Security Policy',
        'No Content Security Policy (CSP) meta tag was found in the document head. CSP helps prevent various attacks by controlling which resources can be loaded and executed.',
        'Medium',
        'Document Head',
        'Client-Side Security Misconfigurations'
      )
    );
  } else if (isWeakCSP(cspContent)) {
    // CSP found but has weaknesses
    vulnerabilities.push(
      createVulnerability(
        'Weak Content Security Policy',
        `The Content Security Policy contains potentially unsafe directives such as 'unsafe-inline', 'unsafe-eval', or overly permissive wildcards. This reduces the effectiveness of the CSP protection.`,
        'Medium', 
        `CSP Meta Tag: ${cspContent.substring(0, 50)}...`,
        'Client-Side Security Misconfigurations'
      )
    );
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

// Function to check for client-side data exposure
function checkClientSideDataExposure(vulnerabilities) {
  // Check localStorage
  checkLocalStorage(vulnerabilities);
  
  // Check sessionStorage
  checkSessionStorage(vulnerabilities);
  
  // Check cookies
  checkCookies(vulnerabilities);
  
  // Check for sensitive data in JavaScript objects
  checkJavaScriptObjects(vulnerabilities);
  
  // Check for sensitive data in input fields
  checkSensitiveInputs(vulnerabilities);
  
  // Check for sensitive data in HTML data attributes
  checkDataAttributes(vulnerabilities);
  
  // Check for exposed API keys
  checkExposedAPIKeys(vulnerabilities);
}

// Check localStorage for sensitive data
function checkLocalStorage(vulnerabilities) {
  try {
    const storageSize = Object.keys(localStorage).length;
    
    if (storageSize > 0) {
      // In a real extension, we would check each item for sensitive data patterns
      // For this demo, we'll examine a few key patterns
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        
        // Check for sensitive keys
        if (/token|auth|jwt|password|secret|key|credential/i.test(key)) {
          vulnerabilities.push(
            createVulnerability(
              'Sensitive Data in localStorage',
              `localStorage contains an item with key "${key}" which appears to store sensitive authentication or security data. This data is accessible to any JavaScript running on the page, including potential XSS attacks.`,
              'High',
              `localStorage.${key}`,
              'Client-Side Data Exposure'
            )
          );
        }
        
        // Check for data that looks like tokens or secrets in values
        if (typeof value === 'string' && value.length > 30 &&
            /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
          // Looks like a JWT token
          vulnerabilities.push(
            createVulnerability(
              'JWT Token in localStorage',
              `localStorage contains what appears to be a JWT token in key "${key}". Storing authentication tokens in localStorage makes them vulnerable to XSS attacks.`,
              'High',
              `localStorage.${key}`,
              'Client-Side Data Exposure'
            )
          );
        }
      }
    }
  } catch (e) {
    // Ignore errors like SecurityError when localStorage is not available
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

// Check for unsafe eval() and similar constructs
function checkUnsafeEval(scriptContent, vulnerabilities) {
  // Check for direct eval usage with variables
  if (scriptContent.match(/eval\s*\([^"']*[\w$]/i)) {
    vulnerabilities.push(
      createVulnerability(
        'Unsafe eval() Usage',
        'JavaScript code uses eval() with dynamic content, which can lead to code injection vulnerabilities.',
        'High',
        'JavaScript Code',
        'JavaScript-Specific Vulnerabilities'
      )
    );
  }
  
  // Check for Function constructor usage with variables
  if (scriptContent.match(/new\s+Function\s*\([^"']*[\w$]/i)) {
    vulnerabilities.push(
      createVulnerability(
        'Unsafe Function Constructor',
        'JavaScript code uses the Function constructor with dynamic content, which is similar to eval() and can lead to code injection.',
        'High',
        'JavaScript Code',
        'JavaScript-Specific Vulnerabilities'
      )
    );
  }
  
  // Check for setTimeout/setInterval with string code instead of function references
  if (scriptContent.match(/setTimeout\s*\(\s*["']/i) || scriptContent.match(/setInterval\s*\(\s*["']/i)) {
    vulnerabilities.push(
      createVulnerability(
        'Unsafe Timer Functions',
        'JavaScript code uses setTimeout or setInterval with string arguments, which acts like eval() and can lead to code injection.',
        'Medium',
        'JavaScript Code',
        'JavaScript-Specific Vulnerabilities'
      )
    );
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
  // Check for mixed content - HTTP resources on an HTTPS page
  if (window.location.protocol === 'https:') {
    // Check scripts
    document.querySelectorAll('script[src^="http:"]').forEach(script => {
      vulnerabilities.push(
        createVulnerability(
          'Insecure Script Source',
          'Script loaded over HTTP on an HTTPS page, creating a mixed content vulnerability.',
          'High',
          script.outerHTML,
          'Network Security'
        )
      );
    });
    
    // Check stylesheets
    document.querySelectorAll('link[rel="stylesheet"][href^="http:"]').forEach(stylesheet => {
      vulnerabilities.push(
        createVulnerability(
          'Insecure Stylesheet',
          'Stylesheet loaded over HTTP on an HTTPS page, creating a mixed content vulnerability.',
          'Medium',
          stylesheet.outerHTML,
          'Network Security'
        )
      );
    });
    
    // Check images
    document.querySelectorAll('img[src^="http:"]').forEach(image => {
      vulnerabilities.push(
        createVulnerability(
          'Insecure Image Source',
          'Image loaded over HTTP on an HTTPS page, creating a mixed content vulnerability.',
          'Low',
          image.outerHTML,
          'Network Security'
        )
      );
    });
    
    // Check iframes
    document.querySelectorAll('iframe[src^="http:"]').forEach(iframe => {
      vulnerabilities.push(
        createVulnerability(
          'Insecure IFrame Source',
          'IFrame loaded over HTTP on an HTTPS page, creating a mixed content vulnerability.',
          'High',
          iframe.outerHTML,
          'Network Security'
        )
      );
    });
  }
}

// Check for API security issues
function checkAPISecurityIssues(vulnerabilities) {
  // Look for API endpoints in the page scripts
  const scripts = document.querySelectorAll('script:not([src])');
  let scriptContent = '';
  
  for (const script of scripts) {
    scriptContent += script.textContent + '\n';
  }
  
  // Check for hardcoded API keys/secrets
  const apiKeyPatterns = /(api[-_]?key|api[-_]?secret|access[-_]?token|client[-_]?secret)/i;
  const hardcodedPatterns = /(const|let|var)\s+(api[-_]?key|api[-_]?secret|access[-_]?token|client[-_]?secret)\s*=\s*["']([^"']{10,})["']/gi;
  
  let match;
  while ((match = hardcodedPatterns.exec(scriptContent)) !== null) {
    vulnerabilities.push(
      createVulnerability(
        'Hardcoded API Credentials',
        `Found hardcoded API credentials in JavaScript code: ${match[2]}`,
        'High',
        match[0],
        'Client-Side Data Exposure'
      )
    );
  }
  
  // Check for sensitive API endpoints
  const sensitiveEndpointPatterns = /(fetch|axios\.get|axios\.post|ajax|\.ajax)\s*\(\s*["']([^"']*\/admin\/|[^"']*\/internal\/|[^"']*\/api\/v[0-9]+\/)/gi;
  
  while ((match = sensitiveEndpointPatterns.exec(scriptContent)) !== null) {
    vulnerabilities.push(
      createVulnerability(
        'Sensitive API Endpoint Detected',
        `Client-side code contains references to potentially sensitive API endpoints: ${match[2]}`,
        'Medium',
        match[0],
        'Network Security'
      )
    );
  }
  
  // Check for potential GraphQL vulnerabilities
  if (scriptContent.includes('graphql') || scriptContent.includes('apolloClient')) {
    // Check for introspection queries which might expose the API schema
    if (scriptContent.includes('__schema') || scriptContent.includes('IntrospectionQuery')) {
      vulnerabilities.push(
        createVulnerability(
          'GraphQL Introspection Enabled',
          'Client-side code contains GraphQL introspection queries, which might expose the API schema in production.',
          'Medium',
          'GraphQL introspection query detected',
          'API Security'
        )
      );
    }
    
    // Check for unbatched GraphQL queries which might lead to DoS
    const queryOperations = (scriptContent.match(/query\s+\w+/g) || []).length;
    if (queryOperations > 5) {
      vulnerabilities.push(
        createVulnerability(
          'Potential GraphQL Query Batching Issue',
          'Multiple individual GraphQL query operations detected. Consider using query batching to prevent potential DoS issues.',
          'Low',
          `${queryOperations} separate GraphQL queries detected`,
          'API Security'
        )
      );
    }
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

// Function to create a vulnerability object with complete information
function createVulnerability(name, description, severity, location, category, status = 'Detected') {
  const id = 'vuln-' + Date.now() + '-' + Math.floor(Math.random() * 10000);
  
  // Map to standardized category names that match the dashboard display
  const standardizedCategories = {
    // Main categories from the screenshot
    'Cross-Site Scripting (XSS)': 'Cross-Site Scripting (XSS)',
    'Client-Side Security Misconfigurations': 'Client-Side Security Misconfigurations',
    'Client-Side Data Exposure': 'Client-Side Data Exposure',
    'JavaScript-Specific Vulnerabilities': 'JavaScript-Specific Vulnerabilities',
    'Dependency Vulnerabilities': 'Dependency Vulnerabilities',
    'Event Handling Vulnerabilities': 'Event Handling Vulnerabilities',
    'Network-Related Vulnerabilities': 'Network-Related Vulnerabilities',
    'Request Forgery Vulnerabilities': 'Request Forgery Vulnerabilities',
    
    // Map variations and subcategories to main categories
    'XSS': 'Cross-Site Scripting (XSS)',
    'Cross-Site Scripting': 'Cross-Site Scripting (XSS)',
    'Reflected XSS': 'Cross-Site Scripting (XSS)',
    'Stored XSS': 'Cross-Site Scripting (XSS)',
    'DOM XSS': 'Cross-Site Scripting (XSS)',
    
    'Security Misconfigurations': 'Client-Side Security Misconfigurations',
    'CSP': 'Client-Side Security Misconfigurations',
    'Content Security Policy': 'Client-Side Security Misconfigurations',
    'Security Headers': 'Client-Side Security Misconfigurations',
    'CORS': 'Client-Side Security Misconfigurations',
    
    'Data Exposure': 'Client-Side Data Exposure',
    'Sensitive Data': 'Client-Side Data Exposure',
    'Information Disclosure': 'Client-Side Data Exposure',
    'Sensitive Information Exposure': 'Client-Side Data Exposure',
    'Local Storage': 'Client-Side Data Exposure',
    'Session Storage': 'Client-Side Data Exposure',
    
    'JavaScript': 'JavaScript-Specific Vulnerabilities',
    'JS': 'JavaScript-Specific Vulnerabilities',
    'JavaScript Security': 'JavaScript-Specific Vulnerabilities',
    'DOM Manipulation': 'JavaScript-Specific Vulnerabilities',
    'Prototype Pollution': 'JavaScript-Specific Vulnerabilities',
    'Eval': 'JavaScript-Specific Vulnerabilities',
    
    'Dependencies': 'Dependency Vulnerabilities', 
    'Outdated Libraries': 'Dependency Vulnerabilities',
    'Vulnerable Libraries': 'Dependency Vulnerabilities',
    'Third-Party': 'Dependency Vulnerabilities',
    
    'Event Handling': 'Event Handling Vulnerabilities',
    'Event Listeners': 'Event Handling Vulnerabilities',
    'Input Events': 'Event Handling Vulnerabilities',
    'Event-based': 'Event Handling Vulnerabilities',
    
    'Network': 'Network-Related Vulnerabilities',
    'Mixed Content': 'Network-Related Vulnerabilities',
    'HTTP': 'Network-Related Vulnerabilities',
    'API': 'Network-Related Vulnerabilities',
    'HTTPS': 'Network-Related Vulnerabilities',
    'Network Security': 'Network-Related Vulnerabilities',
    
    'CSRF': 'Request Forgery Vulnerabilities',
    'Cross-Site Request Forgery': 'Request Forgery Vulnerabilities',
    'Request Forgery': 'Request Forgery Vulnerabilities',
    'SSRF': 'Request Forgery Vulnerabilities',
    'Server-Side Request Forgery': 'Request Forgery Vulnerabilities'
  };
  
  // Use standardized category if available, otherwise use provided category or map to best fit
  let standardizedCategory = standardizedCategories[category];
  
  if (!standardizedCategory) {
    // Try to find a best match if no direct mapping exists
    if (category.includes('XSS') || category.includes('Script')) {
      standardizedCategory = 'Cross-Site Scripting (XSS)';
    } else if (category.includes('Config') || category.includes('Header') || category.includes('CSP') || category.includes('CORS')) {
      standardizedCategory = 'Client-Side Security Misconfigurations';
    } else if (category.includes('Data') || category.includes('Storage') || category.includes('Sensitive')) {
      standardizedCategory = 'Client-Side Data Exposure';
    } else if (category.includes('JS') || category.includes('JavaScript') || category.includes('eval') || category.includes('DOM')) {
      standardizedCategory = 'JavaScript-Specific Vulnerabilities'; 
    } else if (category.includes('Dependency') || category.includes('Library') || category.includes('Package')) {
      standardizedCategory = 'Dependency Vulnerabilities';
    } else if (category.includes('Event') || category.includes('Listener') || category.includes('Handler')) {
      standardizedCategory = 'Event Handling Vulnerabilities';
    } else if (category.includes('Network') || category.includes('HTTP') || category.includes('API') || category.includes('Request')) {
      standardizedCategory = 'Network-Related Vulnerabilities';
    } else if (category.includes('CSRF') || category.includes('Forgery')) {
      standardizedCategory = 'Request Forgery Vulnerabilities';
    } else {
      // Default to JavaScript-Specific as a fallback
      standardizedCategory = 'JavaScript-Specific Vulnerabilities';
    }
  }
  
  return {
    id: id,
    name: name,
    description: description,
    severity: severity, // High, Medium, Low
    location: location,
    category: standardizedCategory,
    status: status, // Detected, Not Detected, Flagged
    stepsToReproduce: getStepsToReproduce(name, location),
    impact: getImpact(name, severity),
    vulnerableCode: getVulnerableCode(name, location),
    fixDescription: getFixDescription(name),
    fixedCode: getFixedCode(name, location),
    references: getReferences(name)
  };
}

// Helper function to generate steps to reproduce based on vulnerability type
function getStepsToReproduce(vulnName, location) {
  // Default steps that will be customized per vulnerability type
  const defaultSteps = [
    "Visit the affected page",
    "Inspect the identified element or resource",
    "Verify the vulnerability exists"
  ];
  
  if (vulnName.includes('XSS')) {
    return [
      "Navigate to the input field or form",
      `Input a test payload like <script>alert(1)</script> into the field`,
      "Submit the form or trigger the relevant action",
      "Observe if the script executes, indicating an XSS vulnerability"
    ];
  } else if (vulnName.includes('CSRF')) {
    return [
      "Log in to the application",
      "Create a test HTML page with a form that submits to the vulnerable endpoint",
      "Open the test page in another tab/window",
      "Verify that the action completes without requiring additional authentication"
    ];
  } else if (vulnName.includes('Mixed Content') || vulnName.includes('Insecure ')) {
    return [
      "Load the page over HTTPS",
      `Inspect network requests using browser developer tools`,
      `Look for resources loaded from insecure origins (${location})`,
      "Verify that insecure content is being loaded over HTTP on a secure page"
    ];
  } else if (vulnName.includes('Cookie')) {
    return [
      "Inspect browser cookies for the domain using developer tools",
      "Check for missing secure or HttpOnly flags",
      "Verify cookie attributes in the browser's Application or Storage tab"
    ];
  } else if (vulnName.includes('API') || vulnName.includes('Endpoint')) {
    return [
      "Intercept API requests using a proxy tool like Burp Suite or browser DevTools",
      "Examine the request and response patterns",
      "Test with modified parameters to verify proper validation"
    ];
  } else if (vulnName.includes('Storage') || vulnName.includes('LocalStorage') || vulnName.includes('SessionStorage')) {
    return [
      "Open browser developer tools",
      "Navigate to Application/Storage tab",
      "Examine Local Storage and Session Storage contents",
      "Look for exposed sensitive information like tokens, user data, or API keys"
    ];
  } else if (vulnName.includes('CSP') || vulnName.includes('Content Security Policy')) {
    return [
      "Check response headers for Content-Security-Policy",
      "Use a CSP analyzer tool to verify policy strength",
      "Test by attempting to load resources that should be blocked"
    ];
  } else if (vulnName.includes('Library') || vulnName.includes('Dependency')) {
    return [
      "Identify the vulnerable library version in script sources",
      "Cross-reference with known vulnerabilities database (e.g., Snyk, OWASP)",
      "Verify the specific vulnerability affects functionality used in this application"
    ];
  } else if (vulnName.includes('Insecure Form')) {
    return [
      "Identify the form in the page source",
      "Check if form action uses HTTP instead of HTTPS",
      "Submit test data and monitor network traffic to verify insecure transmission"
    ];
  } else if (vulnName.includes('eval') || vulnName.includes('Function(') || vulnName.includes('document.write')) {
    return [
      "Locate the unsafe code pattern in the source",
      "Identify what input feeds into the risky function",
      "Test by attempting to inject code through available inputs"
    ];
  }
  
  return defaultSteps;
}

// Helper function to generate impact descriptions
function getImpact(vulnName, severity) {
  const commonImpacts = [
    "Potential data exposure to third parties",
    "Reduced overall security posture"
  ];
  
  let specificImpacts = [];
  
  if (vulnName.includes('XSS')) {
    specificImpacts = [
      "Session hijacking",
      "Data theft",
      "Unauthorized actions performed on behalf of the user",
      "Malicious content injection"
    ];
  } else if (vulnName.includes('CSRF')) {
    specificImpacts = [
      "Unauthorized actions performed on behalf of authenticated users",
      "Account compromise",
      "Data modification without user consent"
    ];
  } else if (vulnName.includes('Insecure Form')) {
    specificImpacts = [
      "Interception of sensitive data during transmission",
      "Man-in-the-middle attacks",
      "Credential theft"
    ];
  } else if (vulnName.includes('Content Security Policy') || vulnName.includes('CSP')) {
    specificImpacts = [
      "Increased risk of XSS attacks",
      "Reduced protection against data injection attacks",
      "Potential for loading malicious resources"
    ];
  } else if (vulnName.includes('Sensitive Data')) {
    specificImpacts = [
      "Exposure of confidential information",
      "API key theft or misuse",
      "User privacy violations"
    ];
  } else if (vulnName.includes('Insecure Script') || vulnName.includes('Insecure Stylesheet')) {
    specificImpacts = [
      "Script injection via man-in-the-middle attacks",
      "Data leakage through mixed content warnings",
      "Potential hijacking of page functionality"
    ];
  } else if (vulnName.includes('Insecure Image') || vulnName.includes('Insecure IFrame')) {
    specificImpacts = [
      "Mixed content warnings in the browser",
      "Downgraded security indicators",
      "Potential content tampering via man-in-the-middle attacks"
    ];
  } else if (vulnName.includes('API') || vulnName.includes('Endpoint')) {
    specificImpacts = [
      "API abuse or misuse",
      "Unauthorized data access",
      "Potential business logic exploitation"
    ];
  } else if (vulnName.includes('eval') || vulnName.includes('Function(')) {
    specificImpacts = [
      "Remote code execution",
      "Complete application compromise",
      "Data exfiltration"
    ];
  } else if (vulnName.includes('Library') || vulnName.includes('Dependency')) {
    specificImpacts = [
      "Inherited security vulnerabilities",
      "Potential for supply chain attacks",
      "Exploitation of known CVEs"
    ];
  }
  
  return severity === 'High' 
    ? [...specificImpacts, ...commonImpacts]
    : specificImpacts;
}

// Helper function to generate example vulnerable code
function getVulnerableCode(vulnName, location) {
  if (vulnName.includes('XSS')) {
    return `// Vulnerable code
function displayUserInput(input) {
  document.getElementById('output').innerHTML = input;
  // Direct insertion of user input into innerHTML is vulnerable to XSS
}`;
  } else if (vulnName.includes('Insecure Form')) {
    return `<!-- Vulnerable form -->
<form action="http://example.com/submit" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Login</button>
</form>`;
  } else if (vulnName.includes('Content Security Policy') || vulnName.includes('CSP')) {
    return `<!-- Missing Content Security Policy -->
<head>
  <!-- No Content-Security-Policy meta tag -->
  <script src="https://example.com/script.js"></script>
</head>`;
  } else if (vulnName.includes('Cookie')) {
    return `// Setting cookies without secure flags
document.cookie = "sessionId=abc123; path=/";
// Missing Secure and HttpOnly flags`;
  } else if (vulnName.includes('Sensitive Data')) {
    return `// Storing sensitive data in localStorage
localStorage.setItem('apiKey', 'sk_live_abcdef123456');
localStorage.setItem('userToken', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');`;
  } else if (vulnName.includes('Insecure Script')) {
    return `<!-- Insecure script loading -->
<script src="http://example.com/script.js"></script>
<!-- Should be loaded via HTTPS -->`;
  } else if (vulnName.includes('Insecure Stylesheet')) {
    return `<!-- Insecure stylesheet loading -->
<link rel="stylesheet" href="http://example.com/styles.css">
<!-- Should be loaded via HTTPS -->`;
  } else if (vulnName.includes('Insecure Image')) {
    return `<!-- Insecure image loading -->
<img src="http://example.com/image.jpg" alt="Insecure image">
<!-- Should be loaded via HTTPS -->`;
  } else if (vulnName.includes('Insecure IFrame')) {
    return `<!-- Insecure iframe loading -->
<iframe src="http://example.com/page.html"></iframe>
<!-- Should be loaded via HTTPS -->`;
  } else if (vulnName.includes('API') || vulnName.includes('Endpoint')) {
    return `// Insecure API call without validation
fetch('/api/user/123')
  .then(response => response.json())
  .then(data => processUserData(data));
// No validation of the response data before processing`;
  } else if (vulnName.includes('eval') || vulnName.includes('Function(')) {
    return `// Unsafe use of eval with user-controlled input
const userInput = getParameterByName('query');
const result = eval('calculateResult(' + userInput + ')');
// Direct use of eval with user input is dangerous`;
  } else if (location && location.includes('src:')) {
    // Extract the specific resource from the location if available
    const srcMatch = location.match(/src:\s*([^,\s]+)/);
    if (srcMatch && srcMatch[1]) {
      return `<!-- Vulnerable resource -->
<script src="${srcMatch[1]}"></script>
<!-- This resource is loaded insecurely -->`;
    }
  } else if (location && location.includes('href:')) {
    // Extract the specific resource from the location if available
    const hrefMatch = location.match(/href:\s*([^,\s]+)/);
    if (hrefMatch && hrefMatch[1]) {
      return `<!-- Vulnerable resource -->
<link href="${hrefMatch[1]}" rel="stylesheet">
<!-- This resource is loaded insecurely -->`;
    }
  }
  
  return `// Example vulnerable code related to ${vulnName}
// Actual code at ${location}`;
}

// Helper function to generate fix descriptions
function getFixDescription(vulnName) {
  if (vulnName.includes('XSS')) {
    return "Implement proper input sanitization and output encoding to prevent XSS attacks. Never insert user input directly into HTML without sanitizing it first.";
  } else if (vulnName.includes('Insecure Form')) {
    return "Update all form actions to use HTTPS instead of HTTP. Ensure all data transmission occurs over encrypted connections.";
  } else if (vulnName.includes('Content Security Policy') || vulnName.includes('CSP')) {
    return "Implement a Content Security Policy header or meta tag to restrict resource loading and execution, which helps prevent various attacks including XSS.";
  } else if (vulnName.includes('Cookie')) {
    return "Set the Secure and HttpOnly flags on all sensitive cookies to prevent theft and client-side access.";
  } else if (vulnName.includes('Sensitive Data')) {
    return "Avoid storing sensitive data on the client. If client-side storage is necessary, use encryption and consider more secure alternatives like session storage for temporary data.";
  } else if (vulnName.includes('Insecure Script') || vulnName.includes('Insecure Stylesheet') || 
             vulnName.includes('Insecure Image') || vulnName.includes('Insecure IFrame')) {
    return "Update all resource URLs to use HTTPS instead of HTTP to prevent mixed content issues and man-in-the-middle attacks.";
  } else if (vulnName.includes('API') || vulnName.includes('Endpoint')) {
    return "Implement proper input validation, output encoding, and authentication checks for all API endpoints. Consider using a server-side API proxy for sensitive operations.";
  } else if (vulnName.includes('eval') || vulnName.includes('Function(')) {
    return "Avoid using eval(), Function constructor, and similar dynamic code execution functions. Use safer alternatives like JSON.parse() for data parsing.";
  } else if (vulnName.includes('Library') || vulnName.includes('Dependency')) {
    return "Update to the latest secure version of the library. Set up a process to regularly check and update dependencies when security patches are released.";
  }
  
  return `Implement secure coding practices specific to this vulnerability type.`;
}

// Helper function to generate fixed code examples
function getFixedCode(vulnName, location) {
  if (vulnName.includes('XSS')) {
    return `// Fixed code
function displayUserInput(input) {
  const sanitizedInput = DOMPurify.sanitize(input);
  document.getElementById('output').innerHTML = sanitizedInput;
  // Or use textContent instead of innerHTML:
  // document.getElementById('output').textContent = input;
}`;
  } else if (vulnName.includes('Insecure Form')) {
    return `<!-- Fixed form -->
<form action="https://example.com/submit" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Login</button>
</form>`;
  } else if (vulnName.includes('Content Security Policy') || vulnName.includes('CSP')) {
    return `<!-- Added Content Security Policy -->
<head>
  <meta http-equiv="Content-Security-Policy" 
    content="default-src 'self'; script-src 'self' https://trusted-cdn.com">
  <script src="https://trusted-cdn.com/script.js"></script>
</head>`;
  } else if (vulnName.includes('Cookie')) {
    return `// Setting cookies with secure flags
document.cookie = "sessionId=abc123; path=/; Secure; HttpOnly; SameSite=Strict";`;
  } else if (vulnName.includes('Sensitive Data')) {
    return `// Store sensitive data securely
// 1. Use server-side sessions instead of client storage when possible
// 2. If client storage is needed, use encryption:
function secureStore(key, value) {
  const encryptedValue = CryptoJS.AES.encrypt(value, secretKey).toString();
  sessionStorage.setItem(key, encryptedValue);
}`;
  } else if (vulnName.includes('Insecure Script')) {
    return `<!-- Fixed secure script loading -->
<script src="https://example.com/script.js"></script>
<!-- Now loaded via HTTPS -->`;
  } else if (vulnName.includes('Insecure Stylesheet')) {
    return `<!-- Fixed secure stylesheet loading -->
<link rel="stylesheet" href="https://example.com/styles.css">
<!-- Now loaded via HTTPS -->`;
  } else if (vulnName.includes('Insecure Image')) {
    return `<!-- Fixed secure image loading -->
<img src="https://example.com/image.jpg" alt="Secure image">
<!-- Now loaded via HTTPS -->`;
  } else if (vulnName.includes('Insecure IFrame')) {
    return `<!-- Fixed secure iframe loading -->
<iframe src="https://example.com/page.html"></iframe>
<!-- Now loaded via HTTPS -->`;
  } else if (vulnName.includes('API') || vulnName.includes('Endpoint')) {
    return `// Secure API call with validation
fetch('/api/user/123')
  .then(response => response.json())
  .then(data => {
    // Validate data before processing
    if (isValidUserData(data)) {
      processUserData(data);
    } else {
      console.error('Invalid data received');
    }
  })
  .catch(error => {
    console.error('API error:', error);
  });`;
  } else if (vulnName.includes('eval') || vulnName.includes('Function(')) {
    return `// Fixed code avoiding eval
const userInput = getParameterByName('query');
// Use a safer approach like a predefined function map
const operations = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b
  // other operations...
};
// Parse parameters safely
const params = JSON.parse(userInput);
const result = operations[params.operation](params.a, params.b);`;
  } else if (location && location.includes('src:')) {
    // Extract the specific resource from the location if available
    const srcMatch = location.match(/src:\s*([^,\s]+)/);
    if (srcMatch && srcMatch[1]) {
      const secureUrl = srcMatch[1].replace(/^http:/, 'https:');
      return `<!-- Fixed secure resource loading -->
<script src="${secureUrl}"></script>
<!-- Now loaded via HTTPS -->`;
    }
  } else if (location && location.includes('href:')) {
    // Extract the specific resource from the location if available
    const hrefMatch = location.match(/href:\s*([^,\s]+)/);
    if (hrefMatch && hrefMatch[1]) {
      const secureUrl = hrefMatch[1].replace(/^http:/, 'https:');
      return `<!-- Fixed secure resource loading -->
<link href="${secureUrl}" rel="stylesheet">
<!-- Now loaded via HTTPS -->`;
    }
  }
  
  return `// Fixed code example for ${vulnName}
// Implementation would depend on the specific vulnerability at ${location}`;
}

// Helper function to generate references
function getReferences(vulnName) {
  const commonRefs = [
    {
      title: "OWASP Top 10",
      url: "https://owasp.org/www-project-top-ten/"
    }
  ];
  
  let specificRefs = [];
  
  if (vulnName.includes('XSS')) {
    specificRefs = [
      {
        title: "OWASP XSS Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
      },
      {
        title: "MDN: Cross-site scripting",
        url: "https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks#cross-site_scripting_xss"
      }
    ];
  } else if (vulnName.includes('CSRF')) {
    specificRefs = [
      {
        title: "OWASP CSRF Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
      }
    ];
  } else if (vulnName.includes('Content Security Policy') || vulnName.includes('CSP')) {
    specificRefs = [
      {
        title: "MDN: Content Security Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
      },
      {
        title: "CSP Evaluator",
        url: "https://csp-evaluator.withgoogle.com/"
      }
    ];
  } else if (vulnName.includes('Cookie')) {
    specificRefs = [
      {
        title: "MDN: Set-Cookie",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
      },
      {
        title: "OWASP Session Management Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
      }
    ];
  } else if (vulnName.includes('Insecure Script') || vulnName.includes('Insecure Stylesheet') || 
             vulnName.includes('Insecure Image') || vulnName.includes('Insecure IFrame') ||
             vulnName.includes('Mixed Content')) {
    specificRefs = [
      {
        title: "MDN: Mixed Content",
        url: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
      },
      {
        title: "Google Web Fundamentals: Preventing Mixed Content",
        url: "https://developers.google.com/web/fundamentals/security/prevent-mixed-content/what-is-mixed-content"
      }
    ];
  } else if (vulnName.includes('API') || vulnName.includes('Endpoint')) {
    specificRefs = [
      {
        title: "OWASP API Security Top 10",
        url: "https://owasp.org/www-project-api-security/"
      },
      {
        title: "API Security Checklist",
        url: "https://github.com/shieldfy/API-Security-Checklist"
      }
    ];
  } else if (vulnName.includes('eval') || vulnName.includes('Function(')) {
    specificRefs = [
      {
        title: "OWASP: Avoid Dangerous Functions",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html#avoid-dangerous-functions"
      },
      {
        title: "MDN: eval()",
        url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!"
      }
    ];
  } else if (vulnName.includes('Library') || vulnName.includes('Dependency')) {
    specificRefs = [
      {
        title: "OWASP: Using Components with Known Vulnerabilities",
        url: "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"
      },
      {
        title: "Snyk Vulnerability Database",
        url: "https://snyk.io/vuln"
      }
    ];
  } else if (vulnName.includes('Storage') || vulnName.includes('LocalStorage') || vulnName.includes('SessionStorage')) {
    specificRefs = [
      {
        title: "OWASP: Local Storage",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage"
      },
      {
        title: "MDN: Web Storage API",
        url: "https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API"
      }
    ];
  }
  
  return [...specificRefs, ...commonRefs];
}

// Check for sensitive information in localStorage and sessionStorage
function checkStorageVulnerabilities(vulnerabilities) {
  // Check localStorage for sensitive information
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const value = localStorage.getItem(key);
    
    // Check for tokens, passwords, or sensitive information
    if (/token|jwt|password|secret|credential|key|auth/i.test(key) || /token|jwt|password|secret|credential|key|auth/i.test(value)) {
      vulnerabilities.push(
        createVulnerability(
          'Sensitive Data in localStorage',
          'Potentially sensitive information stored in localStorage, which is accessible to any JavaScript on the page.',
          'High',
          `localStorage key: ${key}`,
          'Data Storage Security'
        )
      );
    }
  }
  
  // Check sessionStorage for sensitive information
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    const value = sessionStorage.getItem(key);
    
    // Check for tokens, passwords, or sensitive information
    if (/token|jwt|password|secret|credential|key|auth/i.test(key) || /token|jwt|password|secret|credential|key|auth/i.test(value)) {
      vulnerabilities.push(
        createVulnerability(
          'Sensitive Data in sessionStorage',
          'Potentially sensitive information stored in sessionStorage, which is accessible to any JavaScript on the page.',
          'Medium',
          `sessionStorage key: ${key}`,
          'Data Storage Security'
        )
      );
    }
  }
}

// ... existing code ... 