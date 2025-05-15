# Web Security Analyzer

A Chrome extension that analyzes web pages for security vulnerabilities using AI-powered scanning.

## Features

- **Comprehensive Security Scanning**: Analyzes web pages for OWASP Top 10 vulnerabilities
- **Detailed Reports**: Provides evidence, impact assessment, and remediation steps
- **Practical Testing**: Includes executable test payloads for verification
- **User-Friendly Interface**: Clean, responsive design with severity indicators
- **OWASP Alignment**: References OWASP standards and best practices

## Vulnerabilities Detected

- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure form submissions
- Missing security headers
- Unsafe JavaScript practices
- API endpoint security issues
- Injection vulnerabilities
- Authentication issues
- Sensitive data exposure
- Security misconfigurations

## Installation

### From Source

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/web-security-analyzer.git
   ```

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" using the toggle in the top-right corner

4. Click "Load unpacked" and select the extension directory

5. The extension icon should appear in your browser toolbar

## Usage

1. Navigate to any website you want to analyze

2. Click the Web Security Analyzer icon in your browser toolbar

3. Click "Analyze Page" to start the security scan

4. Review the detailed security analysis results

5. Use the provided test payloads to verify vulnerabilities

6. Follow the remediation steps to address security issues

## Development

### Project Structure

- `manifest.json` - Extension configuration
- `popup.html` - Extension popup interface
- `popup.js` - Popup functionality and UI handling
- `background.js` - Background processing and API communication
- `styles.css` - Styling for the extension
- `content.js` - Content script for page interaction

### Building and Testing

1. Make your changes to the codebase

2. Load the extension in Chrome using "Load unpacked"

3. Test your changes on various websites

4. Use Chrome's developer tools to debug issues

### Demo Video

https://github.com/user-attachments/assets/d76282f0-abef-49b6-bbfe-8ee0b2add04a

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP for security standards and guidelines
- Google's Gemini API for AI-powered analysis
