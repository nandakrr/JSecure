// Set a flag to indicate the content script is loaded
window.jsecureContentScriptLoaded = true;

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extractContent") {
    try {
      const content = extractPageContent();
      sendResponse(content);
    } catch (error) {
      console.error("Error extracting content:", error);
      sendResponse({ error: "Failed to extract page content: " + error.message });
    }
    return true; // Keep the message channel open for async response
  } else if (request.action === "checkContentScriptLoaded") {
    // Respond to ping to check if content script is loaded
    sendResponse({ loaded: true });
    return true;
  }
});

// Function to safely extract page content
function extractPageContent() {
  try {
    // Extract basic page content
    const text = document.body ? document.body.innerText : '';
    
    // Safely extract inputs
    const inputs = [];
    try {
      const inputElements = document.querySelectorAll("input, textarea, select");
      for (const i of inputElements) {
        try {
          inputs.push({
            type: i.type || '',
            name: i.name || '',
            id: i.id || '',
            hasValidation: i.pattern !== null && i.pattern !== '',
            isRequired: !!i.required,
            isReadOnly: !!i.readOnly,
            isDisabled: !!i.disabled
          });
        } catch (e) {
          console.error("Error processing input:", e);
        }
      }
    } catch (e) {
      console.error("Error extracting inputs:", e);
    }
    
    // Safely extract links
    const links = [];
    try {
      const linkElements = document.querySelectorAll("a");
      for (const a of linkElements) {
        try {
          if (a.href) links.push(a.href);
        } catch (e) {
          console.error("Error processing link:", e);
        }
      }
    } catch (e) {
      console.error("Error extracting links:", e);
    }
    
    // Safely extract scripts
    const scripts = [];
    try {
      const scriptElements = document.querySelectorAll("script");
      for (const script of scriptElements) {
        try {
          scripts.push(script.src ? { src: script.src } : { code: script.textContent });
        } catch (e) {
          console.error("Error processing script:", e);
        }
      }
    } catch (e) {
      console.error("Error extracting scripts:", e);
    }
    
    // Safely extract forms
    const forms = [];
    try {
      const formElements = document.querySelectorAll("form");
      for (const form of formElements) {
        try {
          const fields = [];
          try {
            for (const field of form.elements) {
              fields.push({
                name: field.name || '',
                type: field.type || '',
                id: field.id || '',
                required: !!field.required
              });
            }
          } catch (e) {
            console.error("Error processing form fields:", e);
          }
          
          forms.push({
            action: form.action || '',
            method: form.method || '',
            fields: fields,
            hasCSRFToken: Array.from(form.elements).some(el => 
              (el.name && (el.name.toLowerCase().includes('csrf') || 
                          el.name.toLowerCase().includes('token'))) ||
              (el.id && (el.id.toLowerCase().includes('csrf') || 
                        el.id.toLowerCase().includes('token')))
            )
          });
        } catch (e) {
          console.error("Error processing form:", e);
        }
      }
    } catch (e) {
      console.error("Error extracting forms:", e);
    }
    
    // Get other security information
    const apiEndpoints = findPotentialApiEndpoints();
    const securityHeaders = extractSecurityHeaders();
    const domXssPatterns = extractDomManipulationPatterns();
    const corsInfo = analyzeCORSConfiguration();
    
    return { 
      textContent: text, 
      inputs, 
      links,
      scripts,
      forms,
      apiEndpoints,
      securityHeaders,
      domXssPatterns,
      corsInfo
    };
  } catch (error) {
    console.error("Error in extractPageContent:", error);
    return { error: "Failed to extract page content: " + error.message };
  }
}

// Send a message to the background script to confirm the content script is loaded
try {
  chrome.runtime.sendMessage({ action: "contentScriptReady" });
} catch (e) {
  console.error("Failed to send contentScriptReady message:", e);
}

// Function to find potential API endpoints in JavaScript
function findPotentialApiEndpoints() {
  const endpoints = [];
  
  try {
    // Simple regex to find URL patterns in scripts
    const urlPattern = /['"`](https?:\/\/[^'"`]+\/[^'"`]+)['"`]/g;
    const apiPattern = /['"`](\/api\/[^'"`]+)['"`]/g;
    
    // Search in all script tags
    document.querySelectorAll('script').forEach(script => {
      if (!script.textContent) return;
      
      let match;
      while ((match = urlPattern.exec(script.textContent)) !== null) {
        if (match[1].includes('/api/') || match[1].includes('/v1/') || 
            match[1].includes('/rest/') || match[1].includes('/graphql')) {
          endpoints.push(match[1]);
        }
      }
      
      while ((match = apiPattern.exec(script.textContent)) !== null) {
        endpoints.push(match[1]);
      }
    });
    
    return [...new Set(endpoints)]; // Remove duplicates
  } catch (error) {
    console.error("Error finding API endpoints:", error);
    return [];
  }
}

// Extract DOM manipulation patterns that could lead to XSS
function extractDomManipulationPatterns() {
  const patterns = [];
  
  try {
    // Look for common DOM XSS sinks in scripts
    const domXssSinks = [
      'innerHTML', 
      'outerHTML', 
      'document.write', 
      'document.writeln',
      'eval', 
      'setTimeout', 
      'setInterval',
      'location',
      'element.src',
      'element.setAttribute',
      'jQuery.html'
    ];
    
    // Search in all script tags
    document.querySelectorAll('script').forEach(script => {
      if (!script.textContent) return;
      
      domXssSinks.forEach(sink => {
        if (script.textContent.includes(sink)) {
          // Check if the sink is used with user input
          const codeSnippet = script.textContent.substring(
            Math.max(0, script.textContent.indexOf(sink) - 50),
            Math.min(script.textContent.length, script.textContent.indexOf(sink) + 100)
          );
          
          // Only include if it appears to use user input
          const usesUserInput = /location|document\.URL|referrer|input|value|getElementById|querySelector/.test(codeSnippet);
          
          if (usesUserInput) {
            patterns.push({
              sink: sink,
              code: codeSnippet,
              confidence: estimateConfidence(codeSnippet, sink)
            });
          }
        }
      });
    });
    
    // Look for URL parameters being used in the DOM
    const urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach((value, param) => {
      // Check if this parameter is used in the DOM
      if (document.body.innerHTML.includes(param)) {
        // Check if the parameter is sanitized
        const isSanitized = checkForSanitization(param);
        
        patterns.push({
          sink: 'URL parameter in DOM',
          code: `Parameter "${param}" found in DOM content`,
          confidence: isSanitized ? 'low' : 'medium'
        });
      }
    });
    
    return patterns;
  } catch (error) {
    console.error("Error finding DOM XSS patterns:", error);
    return [];
  }
}

// Estimate confidence level of a potential vulnerability
function estimateConfidence(codeSnippet, sink) {
  // Check for sanitization functions
  if (/escapeHTML|sanitize|DOMPurify|createTextNode/.test(codeSnippet)) {
    return 'low'; // Likely sanitized
  }
  
  // Check for framework-specific safe methods
  if (/React\.createElement|dangerouslySetInnerHTML|v-html|ng-bind-html/.test(codeSnippet)) {
    return 'medium'; // Framework-specific handling
  }
  
  // High-risk patterns
  if ((sink === 'eval' || sink === 'setTimeout' || sink === 'setInterval') && 
      /location|document\.URL|referrer|input|value/.test(codeSnippet)) {
    return 'high'; // Direct execution of user input
  }
  
  // Default to medium confidence
  return 'medium';
}

// Check if a parameter appears to be sanitized
function checkForSanitization(param) {
  // Look for common sanitization patterns in scripts
  const scripts = Array.from(document.querySelectorAll('script'));
  
  for (const script of scripts) {
    if (!script.textContent) continue;
    
    // Check if the parameter is used with sanitization
    if (script.textContent.includes(param) && 
        /escapeHTML|sanitize|DOMPurify|createTextNode/.test(script.textContent)) {
      return true;
    }
  }
  
  return false;
}

// Extract security headers for analysis
function extractSecurityHeaders() {
  const headers = {
    hasCSP: false,
    hasXFrameOptions: false,
    hasXSSProtection: false
  };
  
  // Check for CSP in meta tags
  headers.hasCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]') !== null;
  
  // Check for common JS security libraries
  headers.hasDOMPurify = typeof window.DOMPurify !== 'undefined';
  headers.hasJSXSS = document.querySelector('script[src*="xss"]') !== null;
  
  // Detect frameworks
  headers.frameworks = [];
  if (typeof window.React !== 'undefined') headers.frameworks.push('React');
  if (typeof window.angular !== 'undefined') headers.frameworks.push('Angular');
  if (typeof window.Vue !== 'undefined') headers.frameworks.push('Vue.js');
  if (typeof window.jQuery !== 'undefined') headers.frameworks.push('jQuery');
  
  return headers;
}

// Check if a form has CSRF protection
function checkForCSRFToken(form) {
  // Check for common CSRF token field names
  const csrfFieldNames = ['csrf', 'csrf_token', '_csrf', 'xsrf', '_token', 'token', 'authenticity_token'];
  
  // Look for hidden input fields with CSRF-like names
  const hasCSRFInput = Array.from(form.elements).some(field => {
    if (field.type !== 'hidden') return false;
    
    // Check if the field name matches common CSRF token patterns
    return csrfFieldNames.some(name => 
      field.name && field.name.toLowerCase().includes(name.toLowerCase())
    );
  });
  
  if (hasCSRFInput) return true;
  
  // Check for CSRF meta tag
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  if (csrfMeta) return true;
  
  // Check for CSRF in headers (common in AJAX frameworks)
  const hasCSRFHeader = Array.from(document.querySelectorAll('script'))
    .some(script => script.textContent && 
      (script.textContent.includes('X-CSRF-Token') || 
       script.textContent.includes('X-XSRF-Token')));
  
  return hasCSRFHeader;
}

// Analyze CORS configuration
function analyzeCORSConfiguration() {
  const corsInfo = {
    crossOriginRequests: [],
    postMessageUsage: [],
    corsHeaders: {},
    iframeUsage: [],
    misconfigurationRisks: []
  };
  
  try {
    // Look for cross-origin requests in scripts
    document.querySelectorAll('script').forEach(script => {
      if (!script.textContent) return;
      
      // Check for fetch or XMLHttpRequest to other domains
      const fetchMatches = script.textContent.match(/fetch\(['"`](https?:\/\/[^'"`]+)['"`]/g);
      if (fetchMatches) {
        fetchMatches.forEach(match => {
          const url = match.replace(/fetch\(['"`]/, '').replace(/['"`].*/, '');
          if (isCrossOrigin(url)) {
            corsInfo.crossOriginRequests.push({
              type: 'fetch',
              url: url,
              withCredentials: script.textContent.includes('credentials: "include"')
            });
          }
        });
      }
      
      // Check for XMLHttpRequest
      if (script.textContent.includes('XMLHttpRequest') && 
          script.textContent.includes('.open(') && 
          script.textContent.includes('.send(')) {
        
        const xhrMatches = script.textContent.match(/\.open\(['"`][^'"`]+['"`],\s*['"`](https?:\/\/[^'"`]+)['"`]/g);
        if (xhrMatches) {
          xhrMatches.forEach(match => {
            const url = match.replace(/\.open\(['"`][^'"`]+['"`],\s*['"`]/, '').replace(/['"`].*/, '');
            if (isCrossOrigin(url)) {
              corsInfo.crossOriginRequests.push({
                type: 'XMLHttpRequest',
                url: url,
                withCredentials: script.textContent.includes('.withCredentials = true')
              });
            }
          });
        }
      }
      
      // Check for postMessage usage
      if (script.textContent.includes('postMessage(')) {
        const postMessageMatches = script.textContent.match(/postMessage\([^,]+,\s*['"`]([^'"`]+)['"`]/g);
        if (postMessageMatches) {
          postMessageMatches.forEach(match => {
            const targetOrigin = match.replace(/postMessage\([^,]+,\s*['"`]/, '').replace(/['"`].*/, '');
            corsInfo.postMessageUsage.push({
              targetOrigin: targetOrigin,
              isWildcard: targetOrigin === '*',
              code: match
            });
          });
        }
      }
      
      // Check for message event listeners
      if (script.textContent.includes('addEventListener("message"') || 
          script.textContent.includes("addEventListener('message'") ||
          script.textContent.includes('addEventListener(`message`')) {
        
        // Check if origin is verified in the event handler
        const hasOriginCheck = script.textContent.includes('event.origin') || 
                              script.textContent.includes('e.origin') || 
                              script.textContent.includes('evt.origin');
        
        corsInfo.postMessageUsage.push({
          type: 'event listener',
          hasOriginCheck: hasOriginCheck,
          code: script.textContent.substring(
            Math.max(0, script.textContent.indexOf('addEventListener("message"') - 20),
            Math.min(script.textContent.length, script.textContent.indexOf('addEventListener("message"') + 150)
          )
        });
      }
    });
    
    // Check for CORS-related meta tags
    const corsMetaTags = document.querySelectorAll('meta[http-equiv="Access-Control-Allow-Origin"]');
    if (corsMetaTags.length > 0) {
      corsInfo.corsHeaders['Access-Control-Allow-Origin'] = 
        Array.from(corsMetaTags).map(tag => tag.getAttribute('content')).join(', ');
    }
    
    // Check for cross-origin iframes
    document.querySelectorAll('iframe').forEach(iframe => {
      if (iframe.src && isCrossOrigin(iframe.src)) {
        corsInfo.iframeUsage.push({
          src: iframe.src,
          hasAllowSameOrigin: iframe.getAttribute('sandbox') && 
                             iframe.getAttribute('sandbox').includes('allow-same-origin')
        });
      }
    });
    
    // Check for JSONP usage (potential CORS bypass)
    document.querySelectorAll('script[src]').forEach(script => {
      if (script.src && script.src.includes('callback=') && isCrossOrigin(script.src)) {
        corsInfo.misconfigurationRisks.push({
          type: 'JSONP',
          url: script.src,
          risk: 'JSONP can bypass CORS restrictions and may lead to data leakage'
        });
      }
    });
    
    // Check for Access-Control-Allow-Origin header in embedded resources
    const linkElements = document.querySelectorAll('link[rel="stylesheet"], script[src], img[src], video[src], audio[src]');
    linkElements.forEach(el => {
      if (el.src || el.href) {
        const url = el.src || el.href;
        if (isCrossOrigin(url)) {
          // We can't directly check headers, but we can note the cross-origin resource
          corsInfo.crossOriginRequests.push({
            type: el.tagName.toLowerCase(),
            url: url,
            note: 'Cross-origin resource embedding'
          });
        }
      }
    });
    
    return corsInfo;
  } catch (error) {
    console.error("Error analyzing CORS:", error);
    return { error: error.message };
  }
}

// Check if a URL is cross-origin
function isCrossOrigin(url) {
  try {
    const currentOrigin = window.location.origin;
    const urlObj = new URL(url);
    return urlObj.origin !== currentOrigin;
  } catch (e) {
    return false;
  }
}






