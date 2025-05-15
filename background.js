// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeContent") {
    analyzeContent(request.content, request.apiKey)
      .then(result => sendResponse({analysis: result}))
      .catch(error => sendResponse({error: error.message}));
    return true; // Required for async response
  }
});

// Function to analyze content using Gemini API
async function analyzeContent(content, apiKey) {
  try {
    // Prepare the content for analysis
    // Limit the size to avoid exceeding API limits
    const preparedContent = JSON.stringify({
      textContent: content.textContent?.substring(0, 5000) || '',
      inputs: content.inputs?.slice(0, 50) || [],
      forms: content.forms?.slice(0, 10) || [],
      scripts: content.scripts?.slice(0, 20) || [],
      inlineEvents: content.inlineEvents?.slice(0, 20) || [],
      securityHeaders: content.securityHeaders || {},
      apiEndpoints: content.apiEndpoints?.slice(0, 20) || []
    });
    
    // Create the prompt for Gemini
    const prompt = `
      You are a web security expert specializing in OWASP Top 10 vulnerabilities. Analyze this website content for security vulnerabilities.
      Focus on identifying:
      1. Cross-Site Scripting (XSS) vulnerabilities (OWASP A03:2021)
      2. Cross-Site Request Forgery (CSRF) risks (OWASP A05:2021)
      3. Insecure form submissions (OWASP A07:2021)
      4. Missing security headers (OWASP A05:2021)
      5. Potentially unsafe JavaScript practices (OWASP A03:2021)
      6. API endpoint security issues (OWASP A09:2021)
      7. Injection vulnerabilities (OWASP A03:2021)
      8. Broken authentication (OWASP A07:2021)
      9. Sensitive data exposure (OWASP A02:2021)
      10. Security misconfiguration (OWASP A05:2021)
      
      Website content data:
      ${preparedContent}
      
      For each vulnerability you find, provide:
      1. A title with severity in parentheses at the end (e.g., "Clickjacking (MEDIUM)")
      2. EVIDENCE: Technical evidence from the page that indicates this vulnerability
      3. IMPACT: What an attacker could do by exploiting this vulnerability
      4. REMEDIATION: How to fix the vulnerability with specific code examples when possible
      5. TEST PAYLOAD: A detailed, realistic payload or code that could be used to test or exploit this vulnerability
      
      Format each vulnerability EXACTLY as follows:
      
      Vulnerability Title (SEVERITY)
      
      EVIDENCE:
      [Technical evidence]
      
      IMPACT:
      [What an attacker could do]
      
      REMEDIATION:
      [How to fix it]
      
      TEST PAYLOAD:
      [Sample payload or code to test/exploit the vulnerability]
      
      Use one of these severity labels: CRITICAL, HIGH, MEDIUM, LOW.
      
      Start your response with "Security Analysis Results:" as a title.
      
      IMPORTANT: 
      - Make sure each vulnerability section is clearly separated with blank lines between them
      - Always include the severity in parentheses at the end of each vulnerability title
      - Always use the exact section headers: EVIDENCE:, IMPACT:, REMEDIATION:, and TEST PAYLOAD:
      - Do not number the vulnerabilities in your response
      - For TEST PAYLOAD section:
        - Provide practical, executable test payloads that demonstrate the vulnerability
        - Avoid using angle brackets directly in XSS payloads, use HTML entities instead (e.g., &lt; instead of <)
        - For JavaScript payloads, use simple alerts or console.log statements that are easy to test
        - Include clear instructions on how to use the payload
      - Reference OWASP guidelines and best practices in your remediation advice
      - Make sure there is a blank line between each vulnerability section
      - DO NOT include any additional text between vulnerability sections
    `;
    
    // Call the Gemini API
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: prompt
          }]
        }]
      })
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(`API error: ${errorData.error?.message || response.statusText}`);
    }
    
    const data = await response.json();
    
    // Extract the text from the response
    const text = data.candidates[0]?.content?.parts[0]?.text;
    if (!text) {
      throw new Error("No response from Gemini API");
    }
    
    // Return the text directly
    return text;
  } catch (error) {
    console.error("Analysis error:", error);
    throw error;
  }
}

// Pre-analyze content to filter out likely false positives
function preAnalyzeForFalsePositives(inputs, links, forms) {
  // Filter inputs that are unlikely to be vulnerable
  const filteredInputs = inputs.filter(input => {
    // Skip hidden inputs, as they're rarely exploitable
    if (input.type === "hidden") return false;
    
    // Skip disabled or readonly inputs
    if (input.isDisabled || input.isReadOnly) return false;
    
    // Skip inputs with strict client-side validation
    if (input.hasValidation && input.isRequired) return false;
    
    // Include all other inputs
    return true;
  });
  
  // Filter links that are unlikely to be vulnerable
  const filteredLinks = links.filter(link => {
    // Skip links to static resources
    if (/\.(jpg|jpeg|png|gif|svg|css|js|woff|ttf)(\?|$)/i.test(link)) return false;
    
    // Skip links to common third-party domains that are unlikely to be vulnerable
    const commonSafeDomains = [
      'googleapis.com', 'gstatic.com', 'jquery.com', 'cloudflare.com',
      'bootstrapcdn.com', 'fontawesome.com'
    ];
    
    if (commonSafeDomains.some(domain => link.includes(domain))) return false;
    
    // Include all other links
    return true;
  });
  
  // Filter forms that are unlikely to be vulnerable
  const filteredForms = forms.filter(form => {
    // Skip forms with only file uploads
    const hasOnlyFileUploads = form.fields && 
      form.fields.length > 0 && 
      form.fields.every(field => field.type === 'file');
    
    if (hasOnlyFileUploads) return false;
    
    // Skip forms with CSRF protection
    if (form.hasCSRFToken) return false;
    
    // Include all other forms
    return true;
  });
  
  return { filteredInputs, filteredLinks, filteredForms };
}

// Analyze security context to help reduce false positives
function analyzeSecurityContext(securityHeaders) {
  const context = [];
  
  // Check for Content Security Policy
  if (securityHeaders.hasCSP) {
    context.push("Content-Security-Policy is present, which may mitigate some XSS attacks");
  }
  
  // Check for common JS frameworks that provide XSS protection
  const frameworks = detectFrameworks();
  if (frameworks.length > 0) {
    context.push(`Detected frameworks: ${frameworks.join(', ')}. Some of these may provide built-in XSS protection.`);
  }
  
  // Check for common sanitization libraries
  const sanitizationLibraries = detectSanitizationLibraries();
  if (sanitizationLibraries.length > 0) {
    context.push(`Detected sanitization libraries: ${sanitizationLibraries.join(', ')}. These may reduce XSS risks.`);
  }
  
  return context.join('\n');
}

// Detect common JS frameworks from global variables
function detectFrameworks() {
  const frameworks = [];
  
  try {
    // This would need to be executed in the context of the page
    // For now, we'll use a simplified approach based on script tags
    const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
      .map(script => script.src.toLowerCase());
    
    if (scriptSrcs.some(src => src.includes('react'))) frameworks.push('React');
    if (scriptSrcs.some(src => src.includes('angular'))) frameworks.push('Angular');
    if (scriptSrcs.some(src => src.includes('vue'))) frameworks.push('Vue.js');
    if (scriptSrcs.some(src => src.includes('jquery'))) frameworks.push('jQuery');
    if (scriptSrcs.some(src => src.includes('ember'))) frameworks.push('Ember.js');
    if (scriptSrcs.some(src => src.includes('backbone'))) frameworks.push('Backbone.js');
    
    return frameworks;
  } catch (error) {
    console.error("Error detecting frameworks:", error);
    return [];
  }
}

// Detect common sanitization libraries
function detectSanitizationLibraries() {
  const libraries = [];
  
  try {
    const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
      .map(script => script.src.toLowerCase());
    
    if (scriptSrcs.some(src => src.includes('dompurify'))) libraries.push('DOMPurify');
    if (scriptSrcs.some(src => src.includes('sanitize'))) libraries.push('sanitize-html');
    if (scriptSrcs.some(src => src.includes('xss'))) libraries.push('js-xss');
    
    return libraries;
  } catch (error) {
    console.error("Error detecting sanitization libraries:", error);
    return [];
  }
}

// Extract JavaScript from script tags and inline event handlers
function extractJavaScript(scripts = []) {
  if (!scripts.length) return "No JavaScript found";
  return scripts.map(s => s.code || s).join("\n\n");
}

// Extract form data for analysis
function extractFormData(forms = []) {
  if (!forms.length) return [];
  return forms.map(form => {
    return {
      action: form.action,
      method: form.method,
      fields: form.fields
    };
  });
}

// Format DOM XSS information for the prompt
function formatDomXssInfo(patterns = []) {
  if (!patterns.length) return "No potential DOM XSS patterns found";
  
  // Filter out patterns that are likely false positives
  const filteredPatterns = patterns.filter(pattern => {
    // Skip patterns that don't involve user input
    if (!pattern.code.includes('location') && 
        !pattern.code.includes('document.URL') && 
        !pattern.code.includes('document.referrer') && 
        !pattern.code.includes('input') && 
        !pattern.code.includes('value')) {
      return false;
    }
    
    return true;
  });
  
  if (!filteredPatterns.length) return "No high-confidence DOM XSS patterns found";
  
  return filteredPatterns.map(pattern => 
    `- Sink: ${pattern.sink}\n  Code: ${pattern.code}`
  ).join("\n\n");
}

// Format CORS information for the prompt
function formatCORSInfo(corsInfo) {
  if (!corsInfo || Object.keys(corsInfo).length === 0) {
    return "No CORS information detected";
  }
  
  let result = [];
  
  // Format cross-origin requests
  if (corsInfo.crossOriginRequests && corsInfo.crossOriginRequests.length > 0) {
    result.push("Cross-Origin Requests:");
    corsInfo.crossOriginRequests.forEach(request => {
      result.push(`- ${request.type} to ${request.url}${request.withCredentials ? ' (with credentials - potential security risk)' : ''}`);
    });
  }
  
  // Format postMessage usage
  if (corsInfo.postMessageUsage && corsInfo.postMessageUsage.length > 0) {
    result.push("\npostMessage Usage:");
    corsInfo.postMessageUsage.forEach(usage => {
      if (usage.targetOrigin) {
        result.push(`- Target origin: ${usage.targetOrigin}${usage.isWildcard ? ' (wildcard "*" - HIGH security risk)' : ''}`);
      } else if (usage.type === 'event listener') {
        result.push(`- Message event listener${usage.hasOriginCheck ? ' (with origin check)' : ' (without origin check - HIGH security risk)'}`);
      }
    });
  }
  
  // Format iframe usage
  if (corsInfo.iframeUsage && corsInfo.iframeUsage.length > 0) {
    result.push("\nCross-Origin iframes:");
    corsInfo.iframeUsage.forEach(iframe => {
      result.push(`- iframe src: ${iframe.src}${iframe.hasAllowSameOrigin ? ' (with allow-same-origin - potential security risk)' : ''}`);
    });
  }
  
  // Format misconfiguration risks
  if (corsInfo.misconfigurationRisks && corsInfo.misconfigurationRisks.length > 0) {
    result.push("\nPotential CORS Misconfigurations:");
    corsInfo.misconfigurationRisks.forEach(risk => {
      result.push(`- ${risk.type}: ${risk.url}`);
      result.push(`  Risk: ${risk.risk}`);
    });
  }
  
  // Format CORS headers
  if (corsInfo.corsHeaders && Object.keys(corsInfo.corsHeaders).length > 0) {
    result.push("\nCORS Headers:");
    for (const [header, value] of Object.entries(corsInfo.corsHeaders)) {
      const riskLevel = value.includes('*') ? ' (wildcard - HIGH security risk)' : '';
      result.push(`- ${header}: ${value}${riskLevel}`);
    }
  }
  
  return result.join("\n");
}





















