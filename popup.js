
document.addEventListener('DOMContentLoaded', async () => {
  const outputEl = document.getElementById("output");
  const analyzeBtn = document.getElementById("analyze");
  
  // Restore previous analysis results if they exist
  try {
    const { analysisResults } = await chrome.storage.local.get("analysisResults");
    if (analysisResults) {
      outputEl.innerHTML = analysisResults;
    }
  } catch (e) {
    console.error("Error restoring previous results:", e);
  }
  
  // Pre-inject the content script when the popup opens
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    
    // Skip injection for non-HTTP/HTTPS pages
    if (tab.url && 
        !tab.url.startsWith("chrome://") && 
        !tab.url.startsWith("chrome-extension://") && 
        !tab.url.startsWith("about:") &&
        !tab.url.startsWith("edge://") &&
        !tab.url.startsWith("brave://") &&
        !tab.url.startsWith("opera://") &&
        !tab.url.startsWith("vivaldi://") &&
        !tab.url.startsWith("file://")) {
      
      // Try to inject the content script
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content.js"]
      }).catch(err => console.log("Pre-injection failed, will try again on analyze: ", err));
    }
  } catch (e) {
    console.log("Error in pre-injection: ", e);
    // Continue anyway, we'll try again when the analyze button is clicked
  }
  
  analyzeBtn.addEventListener("click", async () => {
    try {
      // Show loading state
      outputEl.textContent = "Analyzing page...";
      analyzeBtn.disabled = true;
      
      // Get API key from storage
      const { apiKey } = await chrome.storage.sync.get("apiKey");
      if (!apiKey) {
        outputEl.innerHTML = "<span style='color:red'>Please set your Gemini API key in the options page</span>";
        analyzeBtn.disabled = false;
        return;
      }
      
      // Get the active tab
      const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
      
      // Check if we're on a valid page
      if (!tab.url || 
          tab.url.startsWith("chrome://") || 
          tab.url.startsWith("chrome-extension://") || 
          tab.url.startsWith("about:") ||
          tab.url.startsWith("edge://") ||
          tab.url.startsWith("brave://") ||
          tab.url.startsWith("opera://") ||
          tab.url.startsWith("vivaldi://") ||
          tab.url.startsWith("file://")) {
        outputEl.innerHTML = "<span style='color:red'>Error: JSecure can only analyze HTTP/HTTPS pages. Please navigate to a website first.</span>";
        analyzeBtn.disabled = false;
        return;
      }
      
      // First, check if content script is already loaded
      let contentScriptLoaded = false;
      try {
        const response = await chrome.tabs.sendMessage(tab.id, {action: "checkContentScriptLoaded"});
        contentScriptLoaded = response && response.loaded;
      } catch (error) {
        contentScriptLoaded = false;
      }
      
      // If content script is not loaded, inject it
      if (!contentScriptLoaded) {
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ["content.js"]
          });
          // Wait a moment for the script to initialize
          await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (injectError) {
          console.error("Failed to inject content script:", injectError);
          outputEl.innerHTML = "<span style='color:red'>Error: Cannot access page content. Make sure you're on an HTTP/HTTPS page and the site allows content scripts.</span>";
          analyzeBtn.disabled = false;
          return;
        }
      }
      
      // Now try to extract content via the content script
      try {
        const content = await chrome.tabs.sendMessage(tab.id, {action: "extractContent"});
        
        if (!content || content.error) {
          throw new Error(content?.error || "Failed to extract content");
        }
        
        // Send to background script to make API call
        const analysis = await chrome.runtime.sendMessage({
          action: "analyzeContent",
          content: content,
          apiKey
        });
        
        if (analysis.error) {
          outputEl.innerHTML = `<span style='color:red'>Error: ${analysis.error}</span>`;
        } else {
          // Format the analysis with some basic HTML
          const formattedOutput = formatAnalysisOutput(analysis.analysis);
          outputEl.innerHTML = formattedOutput;
          
          // Save the results to local storage for persistence
          chrome.storage.local.set({ 
            analysisResults: formattedOutput,
            lastAnalyzedUrl: tab.url
          });
        }
      } catch (error) {
        console.error("Content script communication error:", error);
        
        // Fallback to direct script injection if content script fails
        try {
          const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            function: extractPageContent
          });
          
          if (!results || results.length === 0 || !results[0].result) {
            throw new Error("Failed to extract page content");
          }
          
          const pageContent = results[0].result;
          
          // Send to background script to make API call
          const analysis = await chrome.runtime.sendMessage({
            action: "analyzeContent",
            content: pageContent,
            apiKey
          });
          
          if (analysis.error) {
            outputEl.innerHTML = `<span style='color:red'>Error: ${analysis.error}</span>`;
          } else {
            // Format the analysis with some basic HTML
            const formattedOutput = formatAnalysisOutput(analysis.analysis);
            outputEl.innerHTML = formattedOutput;
            
            // Save the results to local storage for persistence
            chrome.storage.local.set({ 
              analysisResults: formattedOutput,
              lastAnalyzedUrl: tab.url
            });
          }
        } catch (scriptError) {
          console.error("Script execution error:", scriptError);
          outputEl.innerHTML = `<span style='color:red'>Error: Could not analyze this page. The site may have security restrictions that prevent content analysis. Try a different website.</span>`;
        }
      }
    } catch (error) {
      console.error("General error:", error);
      outputEl.innerHTML = `<span style='color:red'>Error: ${error.message}</span>`;
    } finally {
      analyzeBtn.disabled = false;
    }
  });
  
  // Add event listener for the options page link
  document.getElementById("openOptions").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
  
  // Add a clear results button
  document.getElementById("clearResults").addEventListener("click", () => {
    chrome.storage.local.remove(["analysisResults", "lastAnalyzedUrl"]);
    outputEl.textContent = "Waiting for analysis...";
  });
});

// This function will be injected into the page context
function extractPageContent() {
  try {
    // Extract basic page content
    const text = document.body ? document.body.innerText.substring(0, 10000) : '';
    
    // Safely extract inputs
    const inputs = [];
    try {
      const inputElements = document.querySelectorAll("input, textarea, select");
      for (let i = 0; i < Math.min(inputElements.length, 100); i++) {
        const elem = inputElements[i];
        try {
          inputs.push({
            type: elem.type || '',
            name: elem.name || '',
            id: elem.id || '',
            hasValidation: elem.pattern !== null && elem.pattern !== '',
            isRequired: !!elem.required,
            isReadOnly: !!elem.readOnly,
            isDisabled: !!elem.disabled
          });
        } catch (e) {
          // Skip this element if there's an error
        }
      }
    } catch (e) {
      // Continue with other extractions
    }
    
    // Safely extract links
    const links = [];
    try {
      const linkElements = document.querySelectorAll("a");
      for (let i = 0; i < Math.min(linkElements.length, 100); i++) {
        try {
          if (linkElements[i].href) links.push(linkElements[i].href);
        } catch (e) {
          // Skip this element if there's an error
        }
      }
    } catch (e) {
      // Continue with other extractions
    }
    
    // Safely extract scripts
    const scripts = [];
    try {
      const scriptElements = document.querySelectorAll("script");
      for (let i = 0; i < Math.min(scriptElements.length, 50); i++) {
        try {
          const script = scriptElements[i];
          if (script.src) {
            scripts.push({ src: script.src });
          } else if (script.textContent) {
            // Limit script content size
            scripts.push({ code: script.textContent.substring(0, 1000) });
          }
        } catch (e) {
          // Skip this element if there's an error
        }
      }
    } catch (e) {
      // Continue with other extractions
    }
    
    // Safely extract forms
    const forms = [];
    try {
      const formElements = document.querySelectorAll("form");
      for (let i = 0; i < Math.min(formElements.length, 20); i++) {
        try {
          const form = formElements[i];
          const fields = [];
          
          try {
            for (let j = 0; j < Math.min(form.elements.length, 30); j++) {
              const field = form.elements[j];
              fields.push({
                name: field.name || '',
                type: field.type || '',
                id: field.id || '',
                required: !!field.required
              });
            }
          } catch (e) {
            // Skip field extraction if there's an error
          }
          
          forms.push({
            action: form.action || '',
            method: form.method || '',
            fields: fields,
            // Check for CSRF token (simple heuristic)
            hasCSRFToken: Array.from(form.elements).some(el => 
              (el.name && (el.name.toLowerCase().includes('csrf') || 
                          el.name.toLowerCase().includes('token'))) ||
              (el.id && (el.id.toLowerCase().includes('csrf') || 
                        el.id.toLowerCase().includes('token')))
            )
          });
        } catch (e) {
          // Skip this form if there's an error
        }
      }
    } catch (e) {
      // Continue with other extractions
    }
    
    // Extract security headers from meta tags
    const securityHeaders = {};
    try {
      const metaTags = document.querySelectorAll('meta');
      for (let i = 0; i < metaTags.length; i++) {
        const meta = metaTags[i];
        if (meta.httpEquiv && meta.content) {
          securityHeaders[meta.httpEquiv.toLowerCase()] = meta.content;
        }
      }
    } catch (e) {
      // Continue with other extractions
    }
    
    return { 
      textContent: text, 
      inputs, 
      links,
      scripts,
      forms,
      securityHeaders
    };
  } catch (error) {
    return { error: "Failed to extract page content: " + error.message };
  }
}

// Function to format the analysis output
function formatAnalysisOutput(analysis) {
  if (!analysis) return "<p>No analysis results available.</p>";
  
  // If analysis is already a string (plain text from API), format it with HTML
  if (typeof analysis === 'string') {
    // Normalize line endings and split by lines
    const lines = analysis.replace(/\r\n/g, '\n').split('\n');
    
    // Identify the main sections
    let vulnerabilities = [];
    let currentVuln = null;
    let mainTitle = '';
    let currentSection = null;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Skip empty lines
      if (!line) continue;
      
      // Check for main title
      if (line.toLowerCase().includes('security analysis results') && !mainTitle) {
        mainTitle = line;
        continue;
      }
      
      // Check for section headers
      if (line === 'EVIDENCE:') {
        if (currentVuln) {
          currentVuln.evidence = [];
          currentSection = 'evidence';
        }
        continue;
      } else if (line === 'IMPACT:') {
        if (currentVuln) {
          currentVuln.impact = [];
          currentSection = 'impact';
        }
        continue;
      } else if (line === 'REMEDIATION:') {
        if (currentVuln) {
          currentVuln.remediation = [];
          currentSection = 'remediation';
        }
        continue;
      } else if (line === 'TEST PAYLOAD:') {
        if (currentVuln) {
          currentVuln.payload = [];
          currentSection = 'payload';
        }
        continue;
      }
      
      // Check for vulnerability title with severity
      const severityMatch = line.match(/(.+?)\s*\((CRITICAL|HIGH|MEDIUM|LOW)\)$/i);
      
      if (severityMatch && 
          !line.includes('EVIDENCE:') && 
          !line.includes('IMPACT:') && 
          !line.includes('REMEDIATION:') && 
          !line.includes('TEST PAYLOAD:')) {
        
        // This is a new vulnerability title
        if (currentVuln) {
          vulnerabilities.push(currentVuln);
        }
        
        currentVuln = {
          title: severityMatch[1].trim(),
          severity: severityMatch[2].toUpperCase(),
          evidence: [],
          impact: [],
          remediation: [],
          payload: []
        };
        
        currentSection = null;
        continue;
      }
      
      // If we're in a section, add the line to that section
      if (currentSection && currentVuln) {
        // Skip empty lines at the beginning of a section
        if (line === '' && currentVuln[currentSection].length === 0) {
          continue;
        }
        currentVuln[currentSection].push(line);
      } else if (currentVuln) {
        // This is content that's part of the vulnerability but not in a specific section
        // For now, we'll ignore it
      } else if (!currentVuln && !mainTitle.toLowerCase().includes(line.toLowerCase()) && line !== '') {
        // This might be a vulnerability title without severity
        // Check if the next line is a section header
        if (i + 1 < lines.length && 
            (lines[i+1].trim() === 'EVIDENCE:' || 
             lines[i+1].trim() === 'IMPACT:' || 
             lines[i+1].trim() === 'REMEDIATION:' || 
             lines[i+1].trim() === 'TEST PAYLOAD:')) {
          
          currentVuln = {
            title: line,
            severity: 'MEDIUM', // Default severity
            evidence: [],
            impact: [],
            remediation: [],
            payload: []
          };
        }
      }
    }
    
    // Add the last vulnerability if there is one
    if (currentVuln) {
      vulnerabilities.push(currentVuln);
    }
    
    // Now build the HTML
    let html = '<div class="analysis-container">';
    
    // Add the main title
    if (mainTitle) {
      html += `<h2>${mainTitle}</h2>`;
    } else {
      html += `<h2>Security Analysis Results</h2>`;
    }
    
    // Add each vulnerability
    vulnerabilities.forEach(vuln => {
      let severityClass = '';
      if (vuln.severity === 'CRITICAL') severityClass = 'critical';
      else if (vuln.severity === 'HIGH') severityClass = 'high';
      else if (vuln.severity === 'MEDIUM') severityClass = 'medium';
      else if (vuln.severity === 'LOW') severityClass = 'low';
      
      html += `<div class="vuln-item">
                <div class="vuln-title">
                  <span>${vuln.title}</span>
                  <span class="severity ${severityClass}">${vuln.severity}</span>
                </div>`;
      
      // Add evidence section
      if (vuln.evidence.length > 0) {
        html += `<div class="vuln-section">
                  <span class="vuln-label">Evidence:</span>
                  <div class="vuln-evidence">`;
        
        // Process the evidence text to handle paragraphs properly
        let paragraphText = '';
        let inCodeBlock = false;
        let codeBlockContent = '';
        
        vuln.evidence.forEach(line => {
          // Check for code block markers
          if (line.startsWith('```') || line.startsWith('~~~')) {
            if (inCodeBlock) {
              // End of code block
              if (paragraphText) {
                html += `<p>${paragraphText}</p>`;
                paragraphText = '';
              }
              html += `<div class="code-block">${codeBlockContent}</div>`;
              codeBlockContent = '';
              inCodeBlock = false;
            } else {
              // Start of code block
              if (paragraphText) {
                html += `<p>${paragraphText}</p>`;
                paragraphText = '';
              }
              inCodeBlock = true;
            }
            return;
          }
          
          if (inCodeBlock) {
            // Add line to code block
            codeBlockContent += line + '\n';
          } else if (line === '') {
            // End of paragraph
            if (paragraphText) {
              html += `<p>${paragraphText}</p>`;
              paragraphText = '';
            }
          } else {
            // Add to current paragraph
            if (paragraphText) {
              paragraphText += ' ' + line;
            } else {
              paragraphText = line;
            }
          }
        });
        
        // Add the last paragraph or code block if there is one
        if (inCodeBlock) {
          html += `<div class="code-block">${codeBlockContent}</div>`;
        } else if (paragraphText) {
          html += `<p>${paragraphText}</p>`;
        }
        
        html += `</div></div>`;
      }
      
      // Add impact section
      if (vuln.impact.length > 0) {
        html += `<div class="vuln-section">
                  <span class="vuln-label">Impact:</span>
                  <div class="vuln-impact">`;
        
        // Process the impact text to handle paragraphs properly
        let paragraphText = '';
        let inCodeBlock = false;
        let codeBlockContent = '';
        
        vuln.impact.forEach(line => {
          // Check for code block markers
          if (line.startsWith('```') || line.startsWith('~~~')) {
            if (inCodeBlock) {
              // End of code block
              if (paragraphText) {
                html += `<p>${paragraphText}</p>`;
                paragraphText = '';
              }
              html += `<div class="code-block">${codeBlockContent}</div>`;
              codeBlockContent = '';
              inCodeBlock = false;
            } else {
              // Start of code block
              if (paragraphText) {
                html += `<p>${paragraphText}</p>`;
                paragraphText = '';
              }
              inCodeBlock = true;
            }
            return;
          }
          
          if (inCodeBlock) {
            // Add line to code block
            codeBlockContent += line + '\n';
          } else if (line === '') {
            // End of paragraph
            if (paragraphText) {
              html += `<p>${paragraphText}</p>`;
              paragraphText = '';
            }
          } else {
            // Add to current paragraph
            if (paragraphText) {
              paragraphText += ' ' + line;
            } else {
              paragraphText = line;
            }
          }
        });
        
        // Add the last paragraph or code block if there is one
        if (inCodeBlock) {
          html += `<div class="code-block">${codeBlockContent}</div>`;
        } else if (paragraphText) {
          html += `<p>${paragraphText}</p>`;
        }
        
        html += `</div></div>`;
      }
      
      // Add remediation section
      if (vuln.remediation.length > 0) {
        html += `<div class="vuln-section">
                  <span class="vuln-label">Remediation:</span>
                  <div class="vuln-remediation">`;
        
        // Process the remediation text to handle paragraphs and code blocks properly
        let paragraphText = '';
        let inCodeBlock = false;
        let codeBlockContent = '';
        
        vuln.remediation.forEach(line => {
          // Check for code block markers
          if (line.startsWith('```') || line.startsWith('~~~')) {
            if (inCodeBlock) {
              // End of code block
              if (paragraphText) {
                html += `<p>${paragraphText}</p>`;
                paragraphText = '';
              }
              html += `<div class="code-block">${codeBlockContent}</div>`;
              codeBlockContent = '';
              inCodeBlock = false;
            } else {
              // Start of code block
              if (paragraphText) {
                html += `<p>${paragraphText}</p>`;
                paragraphText = '';
              }
              inCodeBlock = true;
            }
            return;
          }
          
          if (inCodeBlock) {
            // Add line to code block
            codeBlockContent += line + '\n';
          } else if (line === '') {
            // End of paragraph
            if (paragraphText) {
              html += `<p>${paragraphText}</p>`;
              paragraphText = '';
            }
          } else {
            // Add to current paragraph
            if (paragraphText) {
              paragraphText += ' ' + line;
            } else {
              paragraphText = line;
            }
          }
        });
        
        // Add the last paragraph or code block if there is one
        if (inCodeBlock) {
          html += `<div class="code-block">${codeBlockContent}</div>`;
        } else if (paragraphText) {
          html += `<p>${paragraphText}</p>`;
        }
        
        html += `</div></div>`;
      }
      
      // Add payload section
      if (vuln.payload.length > 0) {
        html += `<div class="vuln-section">
                  <span class="vuln-label">Test Payload:</span>
                  <div class="vuln-payload">`;
        
        // For payload, preserve line breaks and handle HTML entities
        let payloadText = vuln.payload.join('\n');
        
        // Replace angle brackets with HTML entities to avoid filtering
        payloadText = payloadText
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
        
        html += payloadText;
        
        html += `</div></div>`;
      }
      
      html += `</div>`; // Close vuln-item
    });
    
    html += '</div>'; // Close analysis-container
    return html;
  }
  
  // If it's an object (JSON), format it (this is the fallback for backward compatibility)
  let html = `<div class="analysis-container">
    <h2>Security Analysis Results</h2>`;
  
  // Add vulnerabilities section if present
  if (analysis.vulnerabilities && analysis.vulnerabilities.length > 0) {
    html += `<h3>🚨 Potential Vulnerabilities</h3>`;
    analysis.vulnerabilities.forEach(vuln => {
      html += `<p><strong>${vuln.type}</strong>: ${vuln.description}</p>`;
    });
  }
  
  // Add security recommendations
  if (analysis.recommendations && analysis.recommendations.length > 0) {
    html += `<h3>💡 Security Recommendations</h3>`;
    html += `<ul>`;
    analysis.recommendations.forEach(rec => {
      html += `<li>${rec}</li>`;
    });
    html += `</ul>`;
  }
  
  html += `</div>`;
  return html;
}

// Add event listener for the options page link
document.getElementById("openOptions").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

// Add event listener for the code review button if it exists
document.addEventListener('DOMContentLoaded', () => {
  const codeReviewBtn = document.getElementById("codeReview");
  if (codeReviewBtn) {
    codeReviewBtn.addEventListener("click", performCodeReview);
  }
});

// Function to perform code review (if implemented)
async function performCodeReview() {
  // Implementation would go here
}




























