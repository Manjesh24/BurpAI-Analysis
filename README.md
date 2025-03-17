# Burp Suite Extension: AI Pentest Checklist Generator

## Overview

The "Pentest Checklist Generator" is a powerful Burp Suite extension that revolutionizes the initial stages of a penetration test by leveraging the power of Artificial Intelligence. By analyzing the target application's observed HTTP traffic using a locally hosted Large Language Model (LLM), this extension automatically generates a tailored and comprehensive penetration testing checklist.

This extension prioritizes privacy and offline functionality by utilizing a local LLM instance (such as one running via Ollama). All analysis is performed locally without sending sensitive data to external third-party services.

**Key Benefits:**

*   **AI-Powered Checklist Generation:** The extension intelligently analyzes request and response patterns to identify potential vulnerabilities, common attack vectors, and critical areas requiring in-depth testing.
*   **Ensures Comprehensive Test Coverage:**
    *   **For Early-Career Pentesters:** This tool acts as an invaluable assistant, preventing them from overlooking crucial test cases and even providing creative ideas for exploration. It helps build a solid foundation for their assessment.
    *   **For Experienced Pentesters:** Even seasoned professionals can benefit from this extension. The AI-generated checklist provides a high-level overview, helping to catch potentially missed test cases and ensuring a broader test coverage.
*   **Increased Penetration Testing Coverage:** By assisting in the identification of a wider range of potential vulnerabilities and test scenarios, the AI-assisted approach significantly enhances the overall coverage of the penetration test.
*   **Focused and Efficient Assessments:** By providing a prioritized and relevant checklist, the extension empowers penetration testers to conduct more focused and efficient assessments, saving valuable time and resources.

This extension streamlines the penetration testing process, ensuring that no critical area is overlooked and fostering a more thorough and effective security evaluation.

## Features

*   **Local LLM Integration:** Communicates with a locally running LLM (default: Ollama) to perform analysis.
*   **Automated Analysis:** Parses HTTP history from Burp Suite for a selected domain.
*   **Intelligent Checklist Generation:** The LLM identifies potential security weaknesses based on observed endpoints, parameters, data formats, and server responses.
*   **Domain-Focused:** Users can select a specific domain from Burp's site map to target the analysis.
*   **Batch Processing with Progress:** Handles large HTTP histories by processing interactions in configurable batches, with real-time progress updates.
*   **Consolidated Output:** Provides a single, comprehensive penetration testing checklist, aiming to remove redundancies from batch analyses.
*   **Detailed Batch Results:** Retains and displays the checklist generated for each batch of HTTP interactions, allowing for granular review.
*   **Customizable LLM Settings:** Users can configure the API endpoint of their local LLM, the specific model to use, the maximum number of tokens for the LLM's response, and the batch size for processing HTTP history.
*   **Stop and Resume:** Users can interrupt and later resume the checklist generation process, useful for very large applications.
*   **Markdown Export:** The generated consolidated checklist and individual batch checklists can be saved as well-formatted Markdown (`.md`) files for easy sharing and documentation.
*   **Clear Functionality:** Users can easily clear the current results to begin a new analysis.
*   **Contextual Targeting:** A right-click context menu option in Burp Suite allows users to quickly set the domain of a selected HTTP request as the target for checklist generation.
*   **Automatic Save Option:** Upon successful generation, the consolidated checklist can be automatically saved to a designated directory.

## Screenshots
![image](https://github.com/user-attachments/assets/350e0060-6ac2-412a-8af9-04db798d2659)
![image](https://github.com/user-attachments/assets/d5180e4d-7eab-4fb4-b366-3ce454c4df13)
![image](https://github.com/user-attachments/assets/61385a18-76a0-47e5-8d20-ff5111105236)
![image](https://github.com/user-attachments/assets/63c5cac5-d47b-4902-84c5-afa46e5df3ff)
![image](https://github.com/user-attachments/assets/5a3eaf3e-f4fe-4760-bef8-9cab3a43270b)




## Installation

1.  **Ensure Burp Suite is installed.**
2.  **Download the latest release of the `AIChecklist.py` file** from the [BurpAI-Analysis](https://github.com/Manjesh24/BurpAI-Analysis/) page of this repository.
3.  **Open Burp Suite.**
4.  Navigate to the **"Extender"** tab.
5.  Click on the **"Add"** button.
6.  In the "Extension Details" dialog:
    *   Choose **"Python"** as the "Extension type".
    *   Browse to the location where you saved the `AIChecklist.py` file and select it.
7.  Click **"Next"** and then **"Close"**. The "Pentest Checklist Generator" tab should now appear in Burp Suite.

## Prerequisites

*   **Local LLM Setup:** This extension is designed to work with a locally hosted Large Language Model. The default configuration is set for [Ollama](https://ollama.ai/). You need to:
    *   **Install Ollama:** Follow the installation instructions on the Ollama website for your operating system.
    *   **Pull an LLM Model:** Use Ollama to download an appropriate LLM model. The default model configured in the extension is `hf.co/unsloth/gemma-3-27b-it-GGUF:Q4_K_M`. You can change this in the extension's settings. For example:
        ````bash
        ollama pull hf.co/unsloth/gemma-3-27b-it-GGUF:Q4_K_M
        ````
    *   **Ensure Ollama is running:** By default, Ollama runs an API server on `http://localhost:11434`. If your Ollama instance is configured differently, you will need to update the API endpoint in the extension's settings.

## Usage

1.  Navigate to the target web application, begin by capturing all request data from the web application's endpoints, access the sitemap, and remove any irrelevant requests to refine the analysis scope.

2.  Navigate to the **"Pentest Checklist"** tab in Burp Suite.

3.  **Select a Target Domain:**
    *   Click the **"Refresh Domains"** button.
    *   The **"Select Domain"** dropdown menu will be populated with domains currently present in Burp Suite's site map.
    *   Choose the domain you wish to generate a checklist for.

4.  **Configure Settings (Optional):**
    *   Click the **"⚙️"** (settings) button in the top right corner.
    *   A "Settings" dialog will appear, allowing you to configure:
        *   **API Endpoint:** The URL of your local LLM API (default: `http://localhost:11434/api/generate` for Ollama).
        *   **Model Name:** The name of the LLM model to use (default: `hf.co/unsloth/gemma-3-27b-it-GGUF:Q4_K_M`). Ensure this model is available in your local LLM setup.
        *   **Max Tokens:** The maximum number of tokens the LLM should generate in its response (default: `8192`). Adjust this based on your LLM's capabilities and desired checklist detail.
        *   **Batch Size:** The number of HTTP interactions to send to the LLM for analysis in each batch (default: `2`). Adjust this based on the complexity of your target application and the context window of your LLM. A smaller batch size might be more reliable for LLMs with smaller context windows but consumes more time.
    *   Click **"Save"** to apply your settings or **"Cancel"** to discard changes.

5.  **Generate Checklist:**
    *   Once a domain is selected, click the **"Generate Checklist"** button.
    *   The extension will begin processing the HTTP history for the selected domain in batches.
    *   A progress bar and status updates will be displayed in the **"Progress"** panel.

6.  **Review Results:**
    *   The results will be displayed in two tabs:
        *   **"Batch Results"**: This tab shows a list of the batches processed. Selecting a batch from the list on the left will display the raw checklist generated by the LLM for that specific batch on the right. The content is rendered as HTML using Markdown for better readability.
        *   **"Consolidated Checklist"**: This tab displays the final, consolidated penetration testing checklist generated by the LLM after analyzing all batches. This aims to provide a comprehensive and de-duplicated list of testing points. The content is also rendered as HTML using Markdown.

7.  **Control Processing:**
    *   **"Stop"**: If the checklist generation is taking too long or you need to interrupt it, click the **"Stop"** button. The current progress will be halted.
    *   **"Resume"**: If the processing was stopped, the **"Resume"** button will be enabled. Clicking it will attempt to continue the checklist generation from where it was interrupted.

8.  **Save Checklist:**
    *   To save the generated consolidated checklist to a file, click the **"Save Checklist"** button.
    *   A file dialog will appear, allowing you to choose the save location and filename (default filename includes the domain and a timestamp). The checklist will be saved as a Markdown (`.md`) file.
    *   Individual batch checklists are also saved in a subdirectory named `batches_[timestamp]` within the same directory where you save the consolidated checklist.

9.  **Clear Results:**
    *   To clear the currently displayed checklists and prepare for a new analysis, click the **"Clear Results"** button.

10.  **Using Context Menu:**
    *   In any Burp Suite view (e.g., HTTP history, Proxy intercept), you can right-click on an HTTP request.
    *   Select **"Set as Target for Pentest"**. This will automatically select the domain of the clicked request in the "Select Domain" dropdown in the "Pentest Checklist" tab.
  
## Acknowledgements
*   The developers of Ollama and the underlying Large Language Models for making local LLM inference accessible.
