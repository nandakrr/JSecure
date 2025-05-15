document.addEventListener('DOMContentLoaded', async () => {
  // Load saved API key
  const { apiKey } = await chrome.storage.sync.get("apiKey");
  document.getElementById("apiKey").value = apiKey || "";
  
  // Save API key when the save button is clicked
  document.getElementById("saveButton").addEventListener("click", async () => {
    const apiKey = document.getElementById("apiKey").value.trim();
    await chrome.storage.sync.set({ apiKey });
    
    const status = document.getElementById("status");
    status.textContent = "API key saved!";
    setTimeout(() => {
      status.textContent = "";
    }, 3000);
  });
  
  // Add information about getting a Gemini API key
  const apiKeyInfo = document.getElementById("apiKeyInfo");
  if (apiKeyInfo) {
    apiKeyInfo.innerHTML = `
      <p>To get a Gemini API key:</p>
      <ol>
        <li>Go to <a href="https://ai.google.dev/" target="_blank">Google AI Studio</a></li>
        <li>Sign in with your Google account</li>
        <li>Click on "Get API key" in the top right</li>
        <li>Create a new API key or use an existing one</li>
        <li>Copy the API key and paste it here</li>
      </ol>
      <p><strong>Note:</strong> This extension uses the Gemini 2.0 Flash model. Make sure your API key has access to this model.</p>
      <p><strong>Troubleshooting:</strong> If you encounter API errors, verify that your key has access to the gemini-2.0-flash model in the v1beta API.</p>
    `;
  }
});

