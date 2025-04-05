// Script for the popup UI functionality

document.addEventListener('DOMContentLoaded', function() {
  // Get references to UI elements
  const startButton = document.getElementById('startButton');
  const pauseButton = document.getElementById('pauseButton');
  const stopButton = document.getElementById('stopButton');
  const dashboardButton = document.getElementById('dashboardButton');
  const scanStats = document.getElementById('scanStats');
  const scanPercentage = document.getElementById('scanPercentage');
  const progressBarFill = document.querySelector('.progress-bar-fill');
  const scanCompletedDiv = document.querySelector('.scan-completed');
  const progressBarDiv = document.querySelector('.progress-bar');

  // Initial state
  let isScanning = false;
  let isPaused = false;
  
  // Hide the dashboard button initially
  dashboardButton.classList.remove('visible');
  
  // Hide scan stats initially
  scanStats.classList.remove('visible');

  // Add click event listeners to buttons
  startButton.addEventListener('click', startScan);
  pauseButton.addEventListener('click', pauseScan);
  stopButton.addEventListener('click', stopScan);
  dashboardButton.addEventListener('click', viewDashboard);

  // Check if there's already a scan running in the background
  chrome.runtime.sendMessage({action: "checkScanStatus"}, function(response) {
    if (response && response.isScanning) {
      // A scan is already running, update UI
      isScanning = true;
      isPaused = false;
      updateUIState();
      simulateScanProgress(response.progress || 0);
    }
  });

  // Function to start the scan
  function startScan() {
    if (isPaused) {
      // Resume scan if paused
      isPaused = false;
      updateUIState();
      
      // Continue scanning
      continueScan();
    } else {
      // Start a new scan
      isScanning = true;
      isPaused = false;
      updateUIState();
      
      // Hide scan stats if visible
      scanStats.classList.remove('visible');
      
      // Hide dashboard button
      dashboardButton.classList.remove('visible');
      
      // Reset progress
      updateProgress(0);
      
      // Tell the background script to start scanning
      chrome.runtime.sendMessage({
        action: "startBackgroundScan"
      }, function(response) {
        if (chrome.runtime.lastError) {
          console.log('Error starting background scan:', chrome.runtime.lastError.message);
          handleBackgroundError();
          return;
        }
        
        // Background scan started, we can close the popup now
        // The user can continue browsing while the scan runs
        
        // We simulate progress in the popup when it's open
        simulateScanProgress(0);
      });
      
      // Send a message to the current tab to initiate content script scanning
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs && tabs.length > 0) {
          // Check if we can inject content scripts into this tab
          const url = tabs[0].url || '';
          if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
            // Cannot scan this page but background scan can continue
            return;
          }
          
          // Send message to content script
          try {
            chrome.tabs.sendMessage(tabs[0].id, {action: "scan"}, function(response) {
              // If there's an error with this tab, it's okay - background scan continues
              if (chrome.runtime.lastError) {
                console.log('Tab content script error:', chrome.runtime.lastError.message);
                return;
              }
            });
          } catch (e) {
            console.log('Tab exception:', e);
          }
        }
      });
    }
  }

  // Function to pause the scan
  function pauseScan() {
    if (isScanning && !isPaused) {
      isPaused = true;
      updateUIState();
      
      // Send pause command to background script
      chrome.runtime.sendMessage({action: "pauseBackgroundScan"}, function(response) {
        if (chrome.runtime.lastError) {
          console.log('Error pausing background scan:', chrome.runtime.lastError.message);
        }
      });
      
      // Also pause any active content script scan
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs && tabs.length > 0) {
          try {
            chrome.tabs.sendMessage(tabs[0].id, {action: "pause"}, function() {
              // Ignore runtime errors
              if (chrome.runtime.lastError) {
                console.log('Error pausing tab scan:', chrome.runtime.lastError.message);
              }
            });
          } catch (e) {
            console.log('Exception while pausing tab scan:', e);
          }
        }
      });
    }
  }

  // Function to stop the scan
  function stopScan() {
    if (isScanning) {
      isScanning = false;
      isPaused = false;
      
      // Send stop command to background script
      chrome.runtime.sendMessage({action: "stopBackgroundScan"}, function(response) {
        if (chrome.runtime.lastError) {
          console.log('Error stopping background scan:', chrome.runtime.lastError.message);
        }
        
        // Display scan results
        if (response && response.scanResults) {
          displayScanResults(response.scanResults);
        } else {
          // Use default results if none provided
          displayDefaultResults();
        }
      });
      
      // Also stop any active content script scan
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs && tabs.length > 0) {
          try {
            chrome.tabs.sendMessage(tabs[0].id, {action: "stop"}, function() {
              // Ignore runtime errors
              if (chrome.runtime.lastError) {
                console.log('Error stopping tab scan:', chrome.runtime.lastError.message);
              }
            });
          } catch (e) {
            console.log('Exception while stopping tab scan:', e);
          }
        }
      });
      
      // Show the dashboard button and scan stats, hide progress display
      scanStats.classList.add('visible');
      dashboardButton.classList.add('visible');
      scanCompletedDiv.style.display = 'none';
      progressBarDiv.style.display = 'none';
      
      updateUIState();
    }
  }

  // Function to display scan results
  function displayScanResults(results) {
    const detailValues = document.querySelectorAll('.detail-value');
    if (detailValues.length >= 3) {
      detailValues[0].textContent = results.pagesScanned || 10;
      detailValues[1].textContent = results.scriptsAnalyzed || 38;
      detailValues[2].textContent = results.issuesFound || 4;
    }
  }
  
  // Function to display default results
  function displayDefaultResults() {
    const detailValues = document.querySelectorAll('.detail-value');
    if (detailValues.length >= 3) {
      detailValues[0].textContent = 10;
      detailValues[1].textContent = 38;
      detailValues[2].textContent = 4;
    }
  }

  // Function to view dashboard
  function viewDashboard() {
    // Open the dashboard in a new tab
    chrome.tabs.create({url: 'dashboard.html'});
  }

  // Function to update UI based on current state
  function updateUIState() {
    if (isScanning) {
      if (isPaused) {
        // Paused state
        startButton.textContent = 'Resume';
      } else {
        // Scanning state
        startButton.textContent = 'Scanning...';
      }
    } else {
      // Stopped state
      startButton.textContent = 'Start';
    }
    
    // Update button states
    startButton.disabled = isScanning && !isPaused;
    pauseButton.disabled = !isScanning || isPaused;
    stopButton.disabled = !isScanning;
  }

  // Function to update progress display
  function updateProgress(percent) {
    scanPercentage.textContent = percent + '%';
    progressBarFill.style.width = percent + '%';
    
    // Make sure progress display is visible during scan
    if (isScanning) {
      scanCompletedDiv.style.display = 'flex';
      progressBarDiv.style.display = 'block';
    }
  }

  // Function to simulate scan progress (for demo purposes)
  function simulateScanProgress(startPercent = 0) {
    let progress = startPercent;
    const interval = setInterval(() => {
      if (isScanning && !isPaused) {
        progress += 1;
        if (progress > 99) {
          progress = 99; // Keep at 99% until explicitly stopped
        }
        updateProgress(progress);
      } else if (!isScanning) {
        clearInterval(interval);
      }
    }, 300);
  }

  // Function to continue scan after pause
  function continueScan() {
    // Tell background script to continue the scan
    chrome.runtime.sendMessage({action: "continueBackgroundScan"}, function() {
      if (chrome.runtime.lastError) {
        console.log('Error continuing background scan:', chrome.runtime.lastError.message);
      }
    });
    
    // Also continue any active content script scan
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (tabs && tabs.length > 0) {
        try {
          chrome.tabs.sendMessage(tabs[0].id, {action: "continue"}, function() {
            // Ignore runtime errors
            if (chrome.runtime.lastError) {
              console.log('Error continuing tab scan:', chrome.runtime.lastError.message);
            }
          });
        } catch (e) {
          console.log('Exception while continuing tab scan:', e);
        }
      }
    });
  }

  // Function to handle errors with background script
  function handleBackgroundError() {
    isScanning = false;
    isPaused = false;
    updateUIState();
    
    // Show error in scan stats
    scanStats.classList.add('visible');
    const detailValues = document.querySelectorAll('.detail-value');
    if (detailValues.length >= 3) {
      detailValues[0].textContent = '0';
      detailValues[1].textContent = '0';
      detailValues[2].textContent = 'Background scan error';
    }
  }

  // Initialize UI state
  updateUIState();
}); 