// Dashboard script for the Web Security Scanner
document.addEventListener('DOMContentLoaded', function() {
  // Get references to UI elements
  const themeToggle = document.getElementById('theme-toggle');
  const refreshBtn = document.getElementById('refresh-btn');
  const exportBtn = document.getElementById('export-btn');
  const exportDetailBtn = document.getElementById('export-detail-btn');
  const totalIssuesElement = document.getElementById('total-issues');
  const highSeverityElement = document.getElementById('high-severity');
  const mediumSeverityElement = document.getElementById('medium-severity');
  const lowSeverityElement = document.getElementById('low-severity');
  const lastScanTimeElement = document.getElementById('last-scan-time');
  const vulnerabilityCategoriesElement = document.getElementById('vulnerability-categories');
  const modal = document.getElementById('detail-modal');
  const closeModal = document.getElementById('close-modal');
  const searchInput = document.querySelector('input[placeholder="Search vulnerabilities..."]');
  const severityFilter = document.querySelector('select');
  
  // Store vulnerabilities globally for filtering
  let allVulnerabilities = [];
  
  // Current vulnerability being shown in the modal
  let currentVulnerability = null;
  
  // Theme toggle functionality
  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark');
    themeToggle.classList.toggle('active');
  });
  
  // Refresh button functionality
  refreshBtn.addEventListener('click', () => {
    loadData();
  });
  
  // Export button functionality
  exportBtn.addEventListener('click', () => {
    exportReport();
  });
  
  // Export detail button functionality
  exportDetailBtn.addEventListener('click', () => {
    if (currentVulnerability) {
      exportVulnerabilityDetail(currentVulnerability);
    }
  });
  
  // Modal close functionality
  closeModal.addEventListener('click', () => {
    modal.classList.remove('active');
  });
  
  // Close modal when clicking outside
  window.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.classList.remove('active');
    }
  });
  
  // Search functionality
  searchInput.addEventListener('input', () => {
    filterVulnerabilities();
  });
  
  // Severity filter functionality
  severityFilter.addEventListener('change', () => {
    filterVulnerabilities();
  });
  
  // Function to filter vulnerabilities based on search and severity filter
  function filterVulnerabilities() {
    const searchTerm = searchInput.value.trim().toLowerCase();
    const severityValue = severityFilter.value;
    
    let filteredVulnerabilities = [...allVulnerabilities];
    
    // Apply search filter
    if (searchTerm) {
      filteredVulnerabilities = filteredVulnerabilities.filter(vuln => {
        return (
          (vuln.name && vuln.name.toLowerCase().includes(searchTerm)) ||
          (vuln.description && vuln.description.toLowerCase().includes(searchTerm)) ||
          (vuln.category && vuln.category.toLowerCase().includes(searchTerm)) ||
          (vuln.location && vuln.location.toLowerCase().includes(searchTerm))
        );
      });
    }
    
    // Apply severity filter
    if (severityValue !== 'All Severities') {
      filteredVulnerabilities = filteredVulnerabilities.filter(vuln => 
        (vuln.severity || 'Low') === severityValue
      );
    }
    
    // Display filtered vulnerabilities
    displayVulnerabilities(filteredVulnerabilities);
  }
  
  // Load data from storage
  loadData();
  
  // Function to export report as JSON
  function exportReport() {
    chrome.storage.local.get(['lastScanResults', 'lastScanTime', 'vulnerabilities'], function(data) {
      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        alert('No vulnerability data to export');
        return;
      }
      
      const reportData = {
        scanTime: data.lastScanTime || new Date().toISOString(),
        summary: data.lastScanResults || {},
        vulnerabilities: data.vulnerabilities || []
      };
      
      const blob = new Blob([JSON.stringify(reportData, null, 2)], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement('a');
      a.href = url;
      a.download = 'security-scan-report.json';
      document.body.appendChild(a);
      a.click();
      
      setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }, 100);
    });
  }
  
  // Function to ensure all vulnerabilities have IDs
  function ensureVulnerabilityIds(vulnerabilities) {
    if (!vulnerabilities) return [];
    
    return vulnerabilities.map(vuln => {
      if (!vuln.id) {
        // Generate a unique ID if missing
        vuln.id = 'vuln-' + Date.now() + '-' + Math.floor(Math.random() * 10000);
      }
      return vuln;
    });
  }
  
  // Function to load data from Chrome storage
  function loadData() {
    chrome.storage.local.get(['lastScanResults', 'lastScanTime', 'vulnerabilities'], function(data) {
      console.log('Loaded data from storage:', data);
      
      // Check if we have any data
      const hasData = data.lastScanResults || data.lastScanTime || 
                      (data.vulnerabilities && data.vulnerabilities.length > 0);
      
      if (!hasData) {
        // No data available - generate sample data for display purposes
        console.log('No data available, generating sample data');
        const sampleData = generateSampleData();
        allVulnerabilities = sampleData.vulnerabilities;
        displayVulnerabilities(allVulnerabilities);
        updateSummaryStats(sampleData.lastScanResults);
        updateLastScanTime(new Date().toISOString());
        updateCharts(allVulnerabilities);
        return;
      }
      
      // Ensure all vulnerabilities have IDs
      allVulnerabilities = ensureVulnerabilityIds(data.vulnerabilities);
      
      // Update summary stats
      updateSummaryStats(data.lastScanResults);
      
      // Update last scan time
      updateLastScanTime(data.lastScanTime);
      
      // Update charts
      updateCharts(allVulnerabilities);
      
      // Display vulnerabilities
      console.log('Displaying vulnerabilities:', allVulnerabilities);
      displayVulnerabilities(allVulnerabilities);
    });
  }
  
  // Function to generate sample vulnerability data
  function generateSampleData() {
    const timestamp = new Date().toISOString();
    
    const vulnerabilities = [
      // 1. Cross-Site Scripting (XSS)
      {
        id: 'sample-vuln-1',
        name: 'Reflected XSS in Search Form',
        description: 'The search form vulnerable to cross-site scripting attacks through unsanitized input.',
        severity: 'High',
        location: 'search.js:42',
        category: 'Cross-Site Scripting (XSS)',
        status: 'Detected',
        stepsToReproduce: [
          'Navigate to the search form',
          'Input a test payload like <script>alert(1)</script>',
          'Submit the form',
          'Observe the script execution'
        ],
        impact: [
          'Session hijacking',
          'Data theft',
          'Unauthorized actions on behalf of user'
        ],
        vulnerableCode: 'searchResults.innerHTML = "Results for: " + userInput;',
        fixDescription: 'Use safe DOM methods or sanitize input before insertion into HTML.',
        fixedCode: 'searchResults.textContent = "Results for: " + userInput;\n// Or use DOMPurify: searchResults.innerHTML = DOMPurify.sanitize("Results for: " + userInput);',
        references: [
          {
            title: 'OWASP XSS Prevention Cheat Sheet',
            url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
          }
        ],
        timestamp: timestamp
      },
      
      // 2. Client-Side Security Misconfigurations
      {
        id: 'sample-vuln-2',
        name: 'Missing Content Security Policy',
        description: 'The page does not implement a Content Security Policy, leaving it vulnerable to various script injection attacks.',
        severity: 'Medium',
        location: 'index.html',
        category: 'Client-Side Security Misconfigurations',
        status: 'Detected',
        stepsToReproduce: [
          'Inspect the HTTP headers of the page',
          'Note absence of Content-Security-Policy header'
        ],
        impact: [
          'Increased risk of XSS attacks',
          'Reduced protection against data injection'
        ],
        vulnerableCode: '<!DOCTYPE html>\n<html>\n<head>\n  <!-- No CSP header or meta tag -->\n  ...',
        fixDescription: 'Implement a Content Security Policy via HTTP header or meta tag.',
        fixedCode: '<!-- Add in head section -->\n<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'">',
        references: [
          {
            title: 'MDN: Content Security Policy',
            url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
          }
        ],
        timestamp: timestamp
      },
      
      // 3. Client-Side Data Exposure
      {
        id: 'sample-vuln-3',
        name: 'API Key Exposed in Frontend Code',
        description: 'An API key is hardcoded in JavaScript, making it accessible to anyone who views the page source.',
        severity: 'High',
        location: 'api-client.js:12',
        category: 'Client-Side Data Exposure',
        status: 'Detected',
        stepsToReproduce: [
          'View page source or inspect JavaScript files',
          'Find api-client.js',
          'Locate hardcoded API key'
        ],
        impact: [
          'Unauthorized API access',
          'Potential service abuse',
          'Additional costs from API usage'
        ],
        vulnerableCode: 'const apiKey = "AIzaSyB8_s0W_hZ1y0ObvK_T87rTd_UQsxEJRSs";\nconst apiClient = new ApiClient(apiKey);',
        fixDescription: 'Move API key to server-side code and create a proxy endpoint for API requests.',
        fixedCode: '// Client-side\nconst apiClient = new ApiClient();\n\n// Server-side\napp.post(\'/api/proxy\', (req, res) => {\n  const apiKey = process.env.API_KEY; // Stored securely\n  // Make API request with key and return results\n});',
        references: [
          {
            title: 'OWASP Secure Development Practices',
            url: 'https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/'
          }
        ],
        timestamp: timestamp
      },
      
      // 4. Network-Related Vulnerabilities
      {
        id: 'sample-vuln-4',
        name: 'Insecure Form Submission',
        description: 'Login form submits credentials over HTTP instead of HTTPS, exposing sensitive data.',
        severity: 'Medium',
        location: 'login.html:26',
        category: 'Network-Related Vulnerabilities',
        status: 'Detected',
        stepsToReproduce: [
          'Navigate to login page',
          'Inspect the form action URL',
          'Note it uses HTTP protocol'
        ],
        impact: [
          'Credential theft via network sniffing',
          'Man-in-the-middle attacks'
        ],
        vulnerableCode: '<form action="http://example.com/login" method="POST">\n  <!-- Login fields -->\n</form>',
        fixDescription: 'Change form submission to use HTTPS.',
        fixedCode: '<form action="https://example.com/login" method="POST">\n  <!-- Login fields -->\n</form>',
        references: [
          {
            title: 'OWASP Transport Layer Protection',
            url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers'
          }
        ],
        timestamp: timestamp
      },
      
      // 5. Dependency Vulnerabilities
      {
        id: 'sample-vuln-5',
        name: 'Vulnerable jQuery Version',
        description: 'The website is using jQuery v1.8.3 which contains known security vulnerabilities.',
        severity: 'High',
        location: 'jquery.min.js',
        category: 'Dependency Vulnerabilities',
        status: 'Detected',
        stepsToReproduce: [
          'Inspect loaded JavaScript resources',
          'Identify jQuery version from file comments or console output',
          'Verify version against known CVEs'
        ],
        impact: [
          'Remote code execution',
          'Cross-site scripting vulnerability',
          'Data exfiltration'
        ],
        vulnerableCode: '<script src="https://code.jquery.com/jquery-1.8.3.min.js"></script>',
        fixDescription: 'Update to the latest version of jQuery.',
        fixedCode: '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>',
        references: [
          {
            title: 'jQuery Security Advisories',
            url: 'https://jquery.com/upgrade-guide/3.0/#jquery-core'
          }
        ],
        timestamp: timestamp
      },
      
      // 6. Event Handling Vulnerabilities
      {
        id: 'sample-vuln-6',
        name: 'Unvalidated Event Handler User Input',
        description: 'Event handler accepts and processes user input without proper validation.',
        severity: 'Medium',
        location: 'event-handlers.js:37',
        category: 'Event Handling Vulnerabilities',
        status: 'Detected',
        stepsToReproduce: [
          'Interact with the affected UI component',
          'Enter malicious payload in input field',
          'Trigger the event handler',
          'Observe unsafe processing of input'
        ],
        impact: [
          'Client-side data manipulation',
          'Potential script injection',
          'Unexpected application behavior'
        ],
        vulnerableCode: 'element.addEventListener("click", function() {\n  const userValue = document.getElementById("input").value;\n  processData(userValue); // No validation\n});',
        fixDescription: 'Implement input validation before processing user data.',
        fixedCode: 'element.addEventListener("click", function() {\n  const userValue = document.getElementById("input").value;\n  if (validateInput(userValue)) {\n    processData(userValue);\n  } else {\n    showError("Invalid input");\n  }\n});',
        references: [
          {
            title: 'OWASP Input Validation Cheat Sheet',
            url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
          }
        ],
        timestamp: timestamp
      },
      
      // 7. Request Forgery Vulnerabilities
      {
        id: 'sample-vuln-7',
        name: 'CSRF Vulnerability in Form Submission',
        description: 'Form lacks CSRF token, making it vulnerable to cross-site request forgery attacks.',
        severity: 'Medium',
        location: 'profile-update.html:42',
        category: 'Request Forgery Vulnerabilities',
        status: 'Detected',
        stepsToReproduce: [
          'Inspect the form markup',
          'Note the absence of CSRF token',
          'Create a test page that submits to the target endpoint',
          'Verify form processes without validation'
        ],
        impact: [
          'Unauthorized actions performed on behalf of authenticated users',
          'Account compromise',
          'Data modification without user consent'
        ],
        vulnerableCode: '<form action="/update-profile" method="POST">\n  <!-- Form fields without CSRF token -->\n  <button type="submit">Update</button>\n</form>',
        fixDescription: 'Add CSRF token to all forms and validate on the server.',
        fixedCode: '<form action="/update-profile" method="POST">\n  <input type="hidden" name="csrf_token" value="${csrfToken}">\n  <!-- Other form fields -->\n  <button type="submit">Update</button>\n</form>',
        references: [
          {
            title: 'OWASP CSRF Prevention Cheat Sheet',
            url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
          }
        ],
        timestamp: timestamp
      },
      
      // 8. JavaScript-Specific Vulnerabilities
      {
        id: 'sample-vuln-8',
        name: 'Unsafe eval() Usage',
        description: 'JavaScript code uses eval() with user-controlled input, allowing code injection.',
        severity: 'High',
        location: 'main.js:125',
        category: 'JavaScript-Specific Vulnerabilities',
        status: 'Detected',
        stepsToReproduce: [
          'Identify code using eval()',
          'Input malicious JavaScript code as user input',
          'Verify code execution'
        ],
        impact: [
          'Arbitrary code execution',
          'Data theft',
          'Complete compromise of client-side security'
        ],
        vulnerableCode: 'function processUserInput(input) {\n  return eval(input); // Unsafe usage of eval\n}',
        fixDescription: 'Avoid using eval() and use safer alternatives.',
        fixedCode: 'function processUserInput(input) {\n  // Use safer methods to process user input\n  return JSON.parse(input); // If expecting JSON\n  // Or other appropriate parsing/handling based on expected input type\n}',
        references: [
          {
            title: 'OWASP JavaScript Security Guide',
            url: 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'
          }
        ],
        timestamp: timestamp
      }
    ];
    
    const lastScanResults = {
      pagesScanned: 5,
      scriptsAnalyzed: 12,
      issuesFound: vulnerabilities.length,
      highSeverity: vulnerabilities.filter(v => v.severity === 'High').length,
      mediumSeverity: vulnerabilities.filter(v => v.severity === 'Medium').length,
      lowSeverity: vulnerabilities.filter(v => v.severity === 'Low').length
    };
    
    return {
      vulnerabilities: vulnerabilities,
      lastScanResults: lastScanResults
    };
  }
  
  // Function to update empty state
  function updateEmptyState() {
    totalIssuesElement.textContent = '0';
    highSeverityElement.textContent = '0';
    mediumSeverityElement.textContent = '0';
    lowSeverityElement.textContent = '0';
    lastScanTimeElement.textContent = 'No scan performed yet';
    
    vulnerabilityCategoriesElement.innerHTML = `
      <div class="card">
        <div class="text-center p-8">
          <div class="w-16 h-16 flex items-center justify-center bg-gray-100 rounded-full mx-auto mb-4">
            <i class="ri-information-line text-gray-400 ri-2x"></i>
          </div>
          <h3 class="text-lg font-medium mb-2">No Vulnerabilities Detected</h3>
          <p class="text-gray-500">Start a new scan from the extension popup to begin security analysis.</p>
        </div>
      </div>
    `;
  }
  
  // Function to update summary stats
  function updateSummaryStats(results) {
    if (!results) return;
    
    const total = results.issuesFound || 0;
    const high = results.highSeverity || 0;
    const medium = results.mediumSeverity || 0;
    const low = results.lowSeverity || 0;
    
    totalIssuesElement.textContent = total;
    highSeverityElement.textContent = high;
    mediumSeverityElement.textContent = medium;
    lowSeverityElement.textContent = low;
    
    // Update progress bar
    const progress = total > 0 ? (high / total) * 100 : 0;
    document.getElementById('total-issues-progress').style.width = `${progress}%`;
  }
  
  // Function to update last scan time
  function updateLastScanTime(timestamp) {
    if (!timestamp) {
      lastScanTimeElement.textContent = 'No scan performed yet';
      return;
    }
    
    const scanDate = new Date(timestamp);
    const options = { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric', 
      hour: '2-digit', 
      minute: '2-digit' 
    };
    lastScanTimeElement.textContent = scanDate.toLocaleDateString(undefined, options);
  }
  
  // Function to update charts
  function updateCharts(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) return;
    
    // Define chart colors to match the image
    const colors = {
      high: '#FF8A65',    // Coral/salmon color for high
      medium: '#FFB74D',  // Orange for medium
      low: '#4DB6AC'      // Teal for low
    };
    
    // Group vulnerabilities by category and severity
    const categories = {};
    const severities = {
      high: 0,
      medium: 0,
      low: 0
    };
    
    vulnerabilities.forEach(vuln => {
      // Use default severity if missing
      const severity = (vuln.severity || 'Medium').toLowerCase();
      // Use default category if missing
      const category = vuln.category || 'Other Vulnerabilities';
      
      // Update severity counts
      if (severity === 'high') {
        severities.high++;
      } else if (severity === 'medium') {
        severities.medium++;
      } else {
        // Default to low for unknown severities
        severities.low++;
      }
      
      // Group by category
      if (!categories[category]) {
        categories[category] = {
          high: 0,
          medium: 0,
          low: 0
        };
      }
      
      if (severity === 'high') {
        categories[category].high++;
      } else if (severity === 'medium') {
        categories[category].medium++;
      } else {
        categories[category].low++;
      }
    });
    
    // Get short names for categories to display on x-axis
    function getShortName(category) {
      const shortNames = {
        'Cross-Site Scripting (XSS)': 'XSS',
        'Client-Side Security Misconfigurations': 'Misconfig',
        'Client-Side Data Exposure': 'Data Exp',
        'JavaScript-Specific Vulnerabilities': 'JS Vuln',
        'Dependency Vulnerabilities': 'Dependency',
        'Event Handling Vulnerabilities': 'Event',
        'Network-Related Vulnerabilities': 'Network',
        'Request Forgery Vulnerabilities': 'Forgery'
      };
      return shortNames[category] || category;
    }
    
    // Update bar chart
    const barChart = echarts.init(document.getElementById('bar-chart'));
    
    // Sort categories by total vulnerabilities for better visualization
    const sortedCategories = Object.entries(categories).sort((a, b) => {
      const totalA = a[1].high + a[1].medium + a[1].low;
      const totalB = b[1].high + b[1].medium + b[1].low;
      return totalB - totalA;
    });
    
    const categoryNames = sortedCategories.map(entry => getShortName(entry[0]));
    const highData = sortedCategories.map(entry => entry[1].high);
    const mediumData = sortedCategories.map(entry => entry[1].medium);
    const lowData = sortedCategories.map(entry => entry[1].low);
    
    const barOption = {
      title: {
        text: 'Issue Category Distribution',
        left: 'left',
        textStyle: {
          fontSize: 14,
          fontWeight: 'normal'
        }
      },
      animation: false,
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'shadow'
        },
        backgroundColor: 'rgba(255, 255, 255, 0.9)',
        borderColor: '#e5e7eb',
        borderWidth: 1,
        textStyle: {
          color: '#1f2937'
        },
        formatter: function(params) {
          let tooltip = params[0].name + '<br/>';
          let total = 0;
          
          params.forEach(param => {
            tooltip += `<span style="display:inline-block; margin-right:5px; border-radius:10px; width:10px; height:10px; background-color:${param.color};"></span>`;
            tooltip += `${param.seriesName}: ${param.value}<br/>`;
            total += param.value;
          });
          
          tooltip += `<strong>Total: ${total}</strong>`;
          return tooltip;
        }
      },
      legend: {
        data: ['High', 'Medium', 'Low'],
        bottom: 0,
        textStyle: {
          color: '#666'
        },
        itemWidth: 15,
        itemHeight: 10
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '15%',
        top: '15%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        data: categoryNames,
        axisLine: {
          lineStyle: {
            color: '#e5e7eb'
          }
        },
        axisLabel: {
          color: '#666',
          rotate: 0,
          interval: 0
        }
      },
      yAxis: {
        type: 'value',
        axisLine: {
          show: false
        },
        axisTick: {
          show: false
        },
        axisLabel: {
          color: '#666'
        },
        splitLine: {
          lineStyle: {
            color: '#f3f4f6'
          }
        }
      },
      series: [
        {
          name: 'High',
          type: 'bar',
          stack: 'total',
          data: highData,
          itemStyle: {
            color: colors.high,
            borderRadius: [0, 0, 0, 0]
          },
          emphasis: {
            itemStyle: {
              color: colors.high
            }
          }
        },
        {
          name: 'Medium',
          type: 'bar',
          stack: 'total',
          data: mediumData,
          itemStyle: {
            color: colors.medium,
            borderRadius: [0, 0, 0, 0]
          },
          emphasis: {
            itemStyle: {
              color: colors.medium
            }
          }
        },
        {
          name: 'Low',
          type: 'bar',
          stack: 'total',
          data: lowData,
          itemStyle: {
            color: colors.low,
            borderRadius: [0, 0, 0, 0]
          },
          emphasis: {
            itemStyle: {
              color: colors.low
            }
          }
        }
      ]
    };
    barChart.setOption(barOption);
    
    // Update pie chart
    const pieChart = echarts.init(document.getElementById('pie-chart'));
    const pieOption = {
      title: {
        text: 'Severity Breakdown',
        left: 'center',
        textStyle: {
          fontSize: 14,
          fontWeight: 'normal'
        }
      },
      animation: false,
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(255, 255, 255, 0.9)',
        borderColor: '#e5e7eb',
        borderWidth: 1,
        textStyle: {
          color: '#1f2937'
        },
        formatter: function(params) {
          return `${params.name}: ${params.value} (${params.percent.toFixed(1)}%)`;
        }
      },
      legend: {
        orient: 'vertical',
        right: '5%',
        top: 'center',
        textStyle: {
          color: '#666'
        },
        itemWidth: 15,
        itemHeight: 10,
        data: [
          { name: 'High', icon: 'rect' },
          { name: 'Medium', icon: 'rect' },
          { name: 'Low', icon: 'rect' }
        ]
      },
      series: [
        {
          name: 'Severity',
          type: 'pie',
          radius: ['40%', '70%'],
          center: ['40%', '50%'],
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 0,
            borderColor: '#fff',
            borderWidth: 2
          },
          label: {
            show: false
          },
          emphasis: {
            label: {
              show: true,
              fontSize: 14,
              fontWeight: 'bold'
            }
          },
          labelLine: {
            show: false
          },
          data: [
            { value: severities.high, name: 'High', itemStyle: { color: colors.high } },
            { value: severities.medium, name: 'Medium', itemStyle: { color: colors.medium } },
            { value: severities.low, name: 'Low', itemStyle: { color: colors.low } }
          ]
        }
      ]
    };
    pieChart.setOption(pieOption);
    
    // Resize charts when window size changes
    window.addEventListener('resize', () => {
      barChart.resize();
      pieChart.resize();
    });
  }
  
  // Function to display vulnerabilities
  function displayVulnerabilities(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      console.log('No vulnerabilities to display');
      updateEmptyState();
      return;
    }
    
    // Group vulnerabilities by category
    const categories = {};
    vulnerabilities.forEach(vuln => {
      // Assign a default category from our standardized list
      let category = vuln.category || 'Other Vulnerabilities';
      
      // Make sure it's one of our standard categories
      const standardCategories = [
        'Cross-Site Scripting (XSS)',
        'Client-Side Security Misconfigurations',
        'Client-Side Data Exposure',
        'JavaScript-Specific Vulnerabilities',
        'Dependency Vulnerabilities',
        'Event Handling Vulnerabilities',
        'Network-Related Vulnerabilities',
        'Request Forgery Vulnerabilities'
      ];
      
      if (!standardCategories.includes(category)) {
        // Map to closest matching category or default to JavaScript-Specific
        if (category.includes('XSS') || category.includes('Script')) {
          category = 'Cross-Site Scripting (XSS)';
        } else if (category.includes('Configuration') || category.includes('Config')) {
          category = 'Client-Side Security Misconfigurations';
        } else if (category.includes('Data') || category.includes('Exposure')) {
          category = 'Client-Side Data Exposure';
        } else if (category.includes('Network') || category.includes('Content')) {
          category = 'Network-Related Vulnerabilities';
        } else if (category.includes('Dependency') || category.includes('Library')) {
          category = 'Dependency Vulnerabilities';
        } else if (category.includes('Event') || category.includes('Handler')) {
          category = 'Event Handling Vulnerabilities';
        } else if (category.includes('CSRF') || category.includes('Forgery')) {
          category = 'Request Forgery Vulnerabilities';
        } else {
          category = 'JavaScript-Specific Vulnerabilities';
        }
      }
      
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push({...vuln, category: category});
    });
    
    console.log('Grouped vulnerabilities by category:', categories);
    
    // Get category-specific class names for styling
    function getCategoryClasses(category) {
      const baseClasses = {
        'Cross-Site Scripting (XSS)': {
          icon: 'category-icon-xss',
          badge: 'category-badge-xss'
        },
        'Client-Side Security Misconfigurations': {
          icon: 'category-icon-security',
          badge: 'category-badge-security'
        },
        'Client-Side Data Exposure': {
          icon: 'category-icon-data',
          badge: 'category-badge-data'
        },
        'JavaScript-Specific Vulnerabilities': {
          icon: 'category-icon-js',
          badge: 'category-badge-js'
        },
        'Dependency Vulnerabilities': {
          icon: 'category-icon-dependency',
          badge: 'category-badge-dependency'
        },
        'Event Handling Vulnerabilities': {
          icon: 'category-icon-event',
          badge: 'category-badge-event'
        },
        'Network-Related Vulnerabilities': {
          icon: 'category-icon-network',
          badge: 'category-badge-network'
        },
        'Request Forgery Vulnerabilities': {
          icon: 'category-icon-forgery',
          badge: 'category-badge-forgery'
        }
      };
      
      return baseClasses[category] || { icon: '', badge: '' };
    }
    
    // Create HTML for each category
    let html = '';
    let isFirst = true;
    
    // Process categories in a specific order to match the image, starting with XSS
    const orderedCategories = [
      'Cross-Site Scripting (XSS)',
      'Client-Side Security Misconfigurations',
      'Client-Side Data Exposure',
      'JavaScript-Specific Vulnerabilities',
      'Dependency Vulnerabilities',
      'Event Handling Vulnerabilities',
      'Network-Related Vulnerabilities',
      'Request Forgery Vulnerabilities'
    ];
    
    // First process categories in our desired order
    for (const categoryName of orderedCategories) {
      if (categories[categoryName]) {
        const vulns = categories[categoryName];
        // Get category-specific styling classes
        const categoryClasses = getCategoryClasses(categoryName);
        
        // Get issue count
        const totalIssues = vulns.length;
        
        // Determine if this accordion should be open initially
        const isActive = isFirst;
        const activeClass = isActive ? 'active' : '';
        const arrowStyle = isActive ? 'transform: rotate(180deg);' : '';
        const heightStyle = isActive ? `max-height: ${vulns.length * 60 + 100}px;` : '';
        
        html += `
          <div class="accordion">
            <div class="accordion-header flex items-center justify-between p-4 rounded-t">
              <div class="flex items-center">
                <div class="w-8 h-8 flex items-center justify-center rounded-full ${categoryClasses.icon} mr-3">
                  <i class="ri-${getCategoryIcon(categoryName)} ri-lg"></i>
                </div>
                <h3 class="font-medium">${categoryName}</h3>
                <span class="ml-3 px-2 py-1 text-xs font-medium rounded ${categoryClasses.badge}">
                  ${totalIssues} Issues
                </span>
              </div>
              <i class="ri-arrow-down-s-line ri-lg" style="${arrowStyle}"></i>
            </div>
            <div class="accordion-content ${activeClass}" style="${heightStyle}">
              <div class="p-4">
                <div class="overflow-x-auto">
                  <table class="w-full">
                    <thead>
                      <tr class="text-left text-sm font-medium text-gray-500 border-b border-gray-200">
                        <th class="pb-3 pr-4">Type</th>
                        <th class="pb-3 px-4">Severity</th>
                        <th class="pb-3 px-4">Affected Element</th>
                        <th class="pb-3 px-4">Status</th>
                        <th class="pb-3 pl-4">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${vulns.map(vuln => createVulnerabilityRow(vuln)).join('')}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        `;
        
        // After processing the first category, set isFirst to false
        if (isFirst) isFirst = false;
      }
    }
    
    vulnerabilityCategoriesElement.innerHTML = html;
    console.log('Added vulnerability HTML:', html.length > 0);
    
    // Add accordion functionality
    document.querySelectorAll('.accordion-header').forEach(header => {
      header.addEventListener('click', () => {
        const content = header.nextElementSibling;
        const isActive = content.classList.contains('active');
        
        // Close all accordions
        document.querySelectorAll('.accordion-content').forEach(item => {
          item.classList.remove('active');
          item.style.maxHeight = null;
        });
        
        // Toggle the clicked one
        if (!isActive) {
          content.classList.add('active');
          content.style.maxHeight = content.scrollHeight + "px";
        }
        
        // Rotate arrow icon
        document.querySelectorAll('.accordion-header i').forEach(icon => {
          icon.style.transform = 'rotate(0deg)';
        });
        if (!isActive) {
          header.querySelector('i').style.transform = 'rotate(180deg)';
        }
      });
    });
    
    // Add view details functionality
    document.querySelectorAll('.view-details').forEach(button => {
      button.addEventListener('click', () => {
        const vulnId = button.dataset.vulnId;
        // Find vulnerability by ID or index if ID is missing/unknown
        let vuln;
        
        if (vulnId && vulnId !== 'unknown') {
          vuln = allVulnerabilities.find(v => v.id === vulnId);
        }
        
        // If not found or ID was missing, try to find by matching other properties
        if (!vuln && button.closest('tr')) {
          const row = button.closest('tr');
          const vulnName = row.querySelector('td:first-child').textContent;
          const vulnLocation = row.querySelector('td:nth-child(3)').textContent;
          
          vuln = allVulnerabilities.find(v => 
            v.name === vulnName && (v.location || 'N/A') === vulnLocation
          );
        }
        
        if (vuln) {
          showVulnerabilityDetails(vuln);
        } else {
          console.error('Vulnerability not found:', vulnId);
        }
      });
    });
  }
  
  // Function to get category icon
  function getCategoryIcon(category) {
    const icons = {
      'Cross-Site Scripting (XSS)': 'code-line',
      'Client-Side Security Misconfigurations': 'settings-line',
      'Client-Side Data Exposure': 'database-2-line',
      'JavaScript-Specific Vulnerabilities': 'code-s-slash-line',
      'Dependency Vulnerabilities': 'git-branch-line',
      'Event Handling Vulnerabilities': 'cursor-line',
      'Network-Related Vulnerabilities': 'global-line',
      'Request Forgery Vulnerabilities': 'spam-2-line'
    };
    return icons[category] || 'error-warning-line';
  }
  
  // Function to create vulnerability row
  function createVulnerabilityRow(vuln) {
    // Add fallbacks for missing properties
    const severity = vuln.severity || 'Medium';
    const status = vuln.status || 'Detected';
    
    // Map status to colors that match the image
    const statusClasses = {
      'Detected': 'bg-red-100 text-red-800',
      'Flagged': 'bg-orange-100 text-orange-800',
      'Not Detected': 'bg-green-100 text-green-800'
    };
    
    // Map severity to colors that match the image
    const severityClasses = {
      'High': 'bg-red-100 text-red-800',
      'Medium': 'bg-orange-100 text-orange-800',
      'Low': 'bg-yellow-100 text-yellow-800'
    };
    
    const statusClass = statusClasses[status] || statusClasses['Detected'];
    const severityClass = severityClasses[severity] || severityClasses['Medium'];
    
    return `
      <tr class="table-row">
        <td class="py-3 pr-4">${vuln.name || 'Unknown Vulnerability'}</td>
        <td class="py-3 px-4">
          <span class="inline-block px-2 py-1 text-xs font-medium rounded ${severityClass}">
            ${severity}
          </span>
        </td>
        <td class="py-3 px-4 text-sm">${vuln.location || 'N/A'}</td>
        <td class="py-3 px-4">
          <span class="inline-block px-2 py-1 text-xs font-medium rounded ${statusClass}">
            ${status}
          </span>
        </td>
        <td class="py-3 pl-4">
          <button class="view-details px-3 py-1.5 text-sm text-blue-700 border border-blue-700 rounded-button hover:bg-blue-700 hover:text-white whitespace-nowrap" data-vuln-id="${vuln.id || 'unknown'}">
            View Details
          </button>
        </td>
      </tr>
    `;
  }
  
  // Function to show vulnerability details in modal
  function showVulnerabilityDetails(vuln) {
    // Store current vulnerability
    currentVulnerability = vuln;
    
    // Handle missing properties with safe defaults
    const severity = vuln.severity || 'Medium';
    const location = vuln.location || 'Unknown location';
    const description = vuln.description || 'No description available';
    const stepsToReproduce = vuln.stepsToReproduce || ['No steps available'];
    const impact = vuln.impact || ['Impact information not available'];
    const vulnerableCode = vuln.vulnerableCode || 'No code sample available';
    const fixDescription = vuln.fixDescription || 'No fix description available';
    const fixedCode = vuln.fixedCode || 'No fixed code sample available';
    const references = vuln.references || [];
    
    document.getElementById('modal-title').textContent = vuln.name || 'Unknown Vulnerability';
    document.getElementById('modal-severity').textContent = `${severity} Severity`;
    document.getElementById('modal-location').textContent = `Detected in ${location}`;
    document.getElementById('modal-description').textContent = description;
    
    // Update steps to reproduce
    const stepsList = document.getElementById('modal-steps');
    stepsList.innerHTML = stepsToReproduce.map(step => `<li>${step}</li>`).join('');
    
    // Update impact
    const impactList = document.getElementById('modal-impact');
    impactList.innerHTML = impact.map(item => `<li>${item}</li>`).join('');
    
    // Update vulnerable code
    document.getElementById('modal-code').textContent = vulnerableCode;
    
    // Update fix
    document.getElementById('modal-fix-description').textContent = fixDescription;
    document.getElementById('modal-fix-code').textContent = fixedCode;
    
    // Update references
    const referencesList = document.getElementById('modal-references');
    referencesList.innerHTML = references.map(ref => `
      <li>
        <a href="${ref.url || '#'}" class="flex items-center text-primary hover:underline">
          <i class="ri-link mr-2"></i>
          <span>${ref.title || 'Reference'}</span>
        </a>
      </li>
    `).join('') || '<li>No references available</li>';
    
    // Show modal
    modal.classList.add('active');
  }
  
  // Function to export a single vulnerability detail
  function exportVulnerabilityDetail(vuln) {
    const detailData = {
      name: vuln.name,
      severity: vuln.severity,
      location: vuln.location,
      description: vuln.description,
      stepsToReproduce: vuln.stepsToReproduce,
      impact: vuln.impact,
      vulnerableCode: vuln.vulnerableCode,
      fixDescription: vuln.fixDescription,
      fixedCode: vuln.fixedCode,
      references: vuln.references
    };
    
    const blob = new Blob([JSON.stringify(detailData, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability-${vuln.id}.json`;
    document.body.appendChild(a);
    a.click();
    
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }
}); 