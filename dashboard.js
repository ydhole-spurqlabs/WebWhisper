// Dashboard script for the Web Security Scanner
document.addEventListener('DOMContentLoaded', function() {
  // Get references to UI elements
  const pagesScannedElement = document.getElementById('pagesScanned');
  const scriptsAnalyzedElement = document.getElementById('scriptsAnalyzed');
  const issuesFoundElement = document.getElementById('issuesFound');
  const lastScanTimeElement = document.getElementById('lastScanTime');
  const vulnerabilitiesListElement = document.getElementById('vulnerabilitiesList');
  const filterButtons = document.querySelectorAll('.filter-btn');
  
  // Load data from storage
  loadData();
  
  // Add event listeners to filter buttons
  filterButtons.forEach(button => {
    button.addEventListener('click', function() {
      // Remove active class from all buttons
      filterButtons.forEach(btn => btn.classList.remove('active'));
      // Add active class to clicked button
      this.classList.add('active');
      // Apply the filter
      filterVulnerabilities(this.dataset.filter);
    });
  });
  
  // Function to load data from Chrome storage
  function loadData() {
    chrome.storage.local.get(['lastScanResults', 'lastScanTime', 'vulnerabilities', 'vulnHistory'], function(data) {
      // Check if we have any data
      const hasData = data.lastScanResults || data.lastScanTime || 
                      (data.vulnerabilities && data.vulnerabilities.length > 0);
      
      if (!hasData) {
        // No data available - show empty state
        pagesScannedElement.textContent = '0';
        scriptsAnalyzedElement.textContent = '0';
        issuesFoundElement.textContent = '0';
        
        if (lastScanTimeElement) {
          lastScanTimeElement.textContent = 'No scan performed yet';
        }
        
        vulnerabilitiesListElement.innerHTML = `
          <div class="no-vulnerabilities">
            <p>No vulnerabilities detected. Start a new scan from the extension popup.</p>
          </div>
        `;
        return;
      }
      
      // Update summary stats
      updateSummaryStats(data.lastScanResults);
      
      // Update last scan time
      updateLastScanTime(data.lastScanTime);
      
      // Display vulnerabilities
      displayVulnerabilities(data.vulnerabilities, data.vulnHistory);
    });
  }
  
  // Function to update summary stats
  function updateSummaryStats(results) {
    if (!results) return;
    
    pagesScannedElement.textContent = results.pagesScanned || 0;
    scriptsAnalyzedElement.textContent = results.scriptsAnalyzed || 0;
    issuesFoundElement.textContent = results.issuesFound || 0;
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
  
  // Function to display vulnerabilities
  function displayVulnerabilities(vulnerabilities, vulnHistory) {
    // Clear the list first
    vulnerabilitiesListElement.innerHTML = '';
    
    // If there are no vulnerabilities
    if (!vulnerabilities || vulnerabilities.length === 0) {
      vulnerabilitiesListElement.innerHTML = `
        <div class="no-vulnerabilities">
          <p>No vulnerabilities detected. Your pages appear to be secure!</p>
        </div>
      `;
      return;
    }
    
    // Create and append vulnerability items
    vulnerabilities.forEach(vuln => {
      const vulnElement = createVulnerabilityElement(vuln);
      vulnerabilitiesListElement.appendChild(vulnElement);
    });
    
    // Also check the vulnerability history
    if (vulnHistory) {
      for (const url in vulnHistory) {
        if (vulnHistory[url].vulnerabilities && vulnHistory[url].vulnerabilities.length > 0) {
          vulnHistory[url].vulnerabilities.forEach(vuln => {
            // Add URL to vulnerability data
            vuln.url = url;
            const vulnElement = createVulnerabilityElement(vuln);
            vulnerabilitiesListElement.appendChild(vulnElement);
          });
        }
      }
    }
  }
  
  // Function to create a vulnerability element
  function createVulnerabilityElement(vuln) {
    const severityClass = vuln.severity.toLowerCase();
    const severityText = vuln.severity;
    const urlDisplay = vuln.url ? new URL(vuln.url).hostname : 'Unknown URL';
    
    const vulnDiv = document.createElement('div');
    vulnDiv.className = `vuln-item ${severityClass}`;
    vulnDiv.dataset.severity = severityClass;
    
    vulnDiv.innerHTML = `
      <h3>${vuln.name} <span class="vuln-severity ${severityClass}">${severityText}</span></h3>
      <p class="vuln-description">${vuln.description}</p>
      <div class="vuln-meta">
        <span class="vuln-location">${vuln.location || 'N/A'}</span>
        <span class="vuln-url">${urlDisplay}</span>
      </div>
    `;
    
    return vulnDiv;
  }
  
  // Function to filter vulnerabilities by severity
  function filterVulnerabilities(filter) {
    const items = document.querySelectorAll('.vuln-item');
    
    items.forEach(item => {
      if (filter === 'all' || item.dataset.severity === filter) {
        item.style.display = 'block';
      } else {
        item.style.display = 'none';
      }
    });
  }
}); 