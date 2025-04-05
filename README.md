# WebWhisper

WebWhisper is a Chrome extension that passively scans web pages for security vulnerabilities. It helps users identify potential security issues with websites they visit.

## Features

- Scans web pages for common security vulnerabilities
- Detects insecure form submissions
- Identifies mixed content issues (secure pages loading insecure resources)
- Detects use of outdated libraries with known vulnerabilities
- Finds potential exposed sensitive information (like API keys)

## Installation

### From Source Code

1. Download or clone this repository to your computer
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" by toggling the switch in the top-right corner
4. Click "Load unpacked" and select the folder containing the extension files
5. The WebWhisper extension should now appear in your extensions list

### Creating Icon Files

Before using the extension, you'll need to create icon files in the assets folder:
- icon16.png (16x16 pixels)
- icon48.png (48x48 pixels)
- icon128.png (128x128 pixels)

You can use any image editing software to create these icons.

## How to Use

1. Visit any website you want to scan
2. Click on the WebWhisper extension icon in your Chrome toolbar
3. In the popup that appears, click the "Scan for Vulnerabilities" button
4. View the results of the security scan

## Understanding the Results

Vulnerabilities are color-coded by severity:
- **Red border**: High severity issues that should be addressed immediately
- **Yellow border**: Medium severity issues that should be reviewed
- **Green border**: Low severity issues that are typically informational

## Privacy

WebWhisper operates entirely within your browser. No data is sent to external servers, and all scan results are stored locally in your browser.

## Future Improvements

- Additional vulnerability checks
- Scan scheduling
- More detailed explanations and fix recommendations
- CSV export of vulnerability reports
- Settings to customize scan behavior