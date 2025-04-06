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
        displayVulnerabilities(sampleData.vulnerabilities);
        updateSummaryStats(sampleData.lastScanResults);
        updateLastScanTime(new Date().toISOString());
        updateCharts(sampleData.vulnerabilities);
        return;
      }
      
      // Ensure all vulnerabilities have IDs
      const processedVulnerabilities = ensureVulnerabilityIds(data.vulnerabilities);
      
      // Update summary stats
      updateSummaryStats(data.lastScanResults);
      
      // Update last scan time
      updateLastScanTime(data.lastScanTime);
      
      // Update charts
      updateCharts(processedVulnerabilities);
      
      // Display vulnerabilities
      console.log('Displaying vulnerabilities:', processedVulnerabilities);
      displayVulnerabilities(processedVulnerabilities);
    });
  }
  
  // Function to generate sample vulnerability data
  function generateSampleData() {
    const timestamp = new Date().toISOString();
    
    const vulnerabilities = [
      {
        id: 'sample-vuln-1',
        name: 'Reflected XSS in Search Form',
        description: 'The search form vulnerable to cross-site scripting attacks through unsanitized input.',
        severity: 'High',
        location: 'search.js:42',
        category: 'XSS',
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
    
    // Update bar chart
    const barChart = echarts.init(document.getElementById('bar-chart'));
    const barOption = {
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
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        top: '3%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        data: Object.keys(categories),
        axisLine: {
          lineStyle: {
            color: '#e5e7eb'
          }
        },
        axisLabel: {
          color: '#1f2937'
        }
      },
      yAxis: {
        type: 'value',
        axisLine: {
          lineStyle: {
            color: '#e5e7eb'
          }
        },
        axisLabel: {
          color: '#1f2937'
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
          data: Object.values(categories).map(cat => cat.high),
          itemStyle: {
            color: 'rgba(252, 141, 98, 1)',
            borderRadius: [4, 4, 0, 0]
          }
        },
        {
          name: 'Medium',
          type: 'bar',
          stack: 'total',
          data: Object.values(categories).map(cat => cat.medium),
          itemStyle: {
            color: 'rgba(251, 191, 114, 1)',
            borderRadius: [0, 0, 0, 0]
          }
        },
        {
          name: 'Low',
          type: 'bar',
          stack: 'total',
          data: Object.values(categories).map(cat => cat.low),
          itemStyle: {
            color: 'rgba(141, 211, 199, 1)',
            borderRadius: [0, 0, 4, 4]
          }
        }
      ]
    };
    barChart.setOption(barOption);
    
    // Update pie chart
    const pieChart = echarts.init(document.getElementById('pie-chart'));
    const pieOption = {
      animation: false,
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(255, 255, 255, 0.9)',
        borderColor: '#e5e7eb',
        borderWidth: 1,
        textStyle: {
          color: '#1f2937'
        }
      },
      legend: {
        orient: 'vertical',
        right: 10,
        top: 'center',
        textStyle: {
          color: '#1f2937'
        }
      },
      series: [
        {
          name: 'Severity',
          type: 'pie',
          radius: ['40%', '70%'],
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 4,
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
            { value: severities.high, name: 'High', itemStyle: { color: 'rgba(252, 141, 98, 1)' } },
            { value: severities.medium, name: 'Medium', itemStyle: { color: 'rgba(251, 191, 114, 1)' } },
            { value: severities.low, name: 'Low', itemStyle: { color: 'rgba(141, 211, 199, 1)' } }
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
      // Assign a default category if missing
      const category = vuln.category || 'Other Vulnerabilities';
      
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(vuln);
    });
    
    console.log('Grouped vulnerabilities by category:', categories);
    
    // Create HTML for each category
    let html = '';
    for (const [category, vulns] of Object.entries(categories)) {
      // Assign default severity values if missing
      const severityCounts = {
        high: vulns.filter(v => (v.severity || '').toLowerCase() === 'high').length,
        medium: vulns.filter(v => (v.severity || '').toLowerCase() === 'medium').length,
        low: vulns.filter(v => (v.severity || '').toLowerCase() === 'low' || !v.severity).length
      };
      
      const totalIssues = vulns.length;
      const severityClass = severityCounts.high > 0 ? 'high' : 
                          severityCounts.medium > 0 ? 'medium' : 'low';
      
      html += `
        <div class="accordion">
          <div class="accordion-header flex items-center justify-between p-4 rounded-t">
            <div class="flex items-center">
              <div class="w-8 h-8 flex items-center justify-center rounded-full bg-${severityClass}-100 mr-3">
                <i class="ri-${getCategoryIcon(category)} text-${severityClass}-500"></i>
              </div>
              <h3 class="font-medium">${category}</h3>
              <span class="ml-3 px-2 py-1 text-xs font-medium rounded bg-${severityClass}-100 text-${severityClass}-500">
                ${totalIssues} Issues
              </span>
            </div>
            <i class="ri-arrow-down-s-line ri-lg"></i>
          </div>
          <div class="accordion-content">
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
          vuln = vulnerabilities.find(v => v.id === vulnId);
        }
        
        // If not found or ID was missing, try to find by matching other properties
        if (!vuln && button.closest('tr')) {
          const row = button.closest('tr');
          const vulnName = row.querySelector('td:first-child').textContent;
          const vulnLocation = row.querySelector('td:nth-child(3)').textContent;
          
          vuln = vulnerabilities.find(v => 
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
      'XSS': 'code-line',
      'Client-Side Security Misconfigurations': 'settings-line',
      'Client-Side Data Exposure': 'database-2-line',
      'JavaScript-Specific Vulnerabilities': 'code-s-slash-line',
      'Dependency Vulnerabilities': 'git-branch-line',
      'Event Handling Vulnerabilities': 'cursor-line',
      'Network-Related Vulnerabilities': 'global-line',
      'Request Forgery Vulnerabilities': 'spam-2-line',
      'Other Vulnerabilities': 'error-warning-line'
    };
    return icons[category] || 'error-warning-line';
  }
  
  // Function to create vulnerability row
  function createVulnerabilityRow(vuln) {
    // Add fallbacks for missing properties
    const severity = vuln.severity || 'Medium';
    const status = vuln.status || 'Detected';
    const severityClass = severity.toLowerCase();
    const statusClass = status.toLowerCase();
    
    return `
      <tr class="table-row">
        <td class="py-3 pr-4">${vuln.name || 'Unknown Vulnerability'}</td>
        <td class="py-3 px-4">
          <span class="inline-block px-2 py-1 text-xs font-medium rounded severity-${severityClass}">
            ${severity}
          </span>
        </td>
        <td class="py-3 px-4 text-sm">${vuln.location || 'N/A'}</td>
        <td class="py-3 px-4">
          <span class="inline-block px-2 py-1 text-xs font-medium rounded status-${statusClass}">
            ${status}
          </span>
        </td>
        <td class="py-3 pl-4">
          <button class="view-details px-3 py-1.5 text-sm text-primary border border-primary rounded-button hover:bg-primary hover:text-white whitespace-nowrap" data-vuln-id="${vuln.id || 'unknown'}">
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