# Burp Suite Extension: Local LLM Pentest Checklist Generator

## Overview

The "Pentest Checklist Generator" is a Burp Suite extension designed to automate the initial stages of a penetration test by generating a tailored checklist based on the application's observed HTTP traffic. By leveraging a locally hosted Large Language Model (LLM), this extension analyzes requests and responses to identify potential vulnerabilities, common attack vectors, and areas that require closer scrutiny. This empowers penetration testers to conduct more focused and efficient assessments.

This extension prioritizes privacy and offline functionality by utilizing a local LLM instance (such as one running via Ollama). All analysis is performed locally without sending sensitive data to external third-party services.

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

## Installation

1.  **Ensure Burp Suite is installed.**
2.  **Download the latest release of the `AIChecklist.py` file** from the [Releases](https://github.com/Manjesh24/BurpAI-Analysis/releases) page of this repository.
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

1.  Navigate to the **"Pentest Checklist"** tab in Burp Suite.

2.  **Select a Target Domain:**
    *   Click the **"Refresh Domains"** button.
    *   The **"Select Domain"** dropdown menu will be populated with domains currently present in Burp Suite's site map.
    *   Choose the domain you wish to generate a checklist for.

3.  **Configure Settings (Optional):**
    *   Click the **"⚙️"** (settings) button in the top right corner.
    *   A "Settings" dialog will appear, allowing you to configure:
        *   **API Endpoint:** The URL of your local LLM API (default: `http://localhost:11434/api/generate` for Ollama).
        *   **Model Name:** The name of the LLM model to use (default: `hf.co/unsloth/gemma-3-27b-it-GGUF:Q4_K_M`). Ensure this model is available in your local LLM setup.
        *   **Max Tokens:** The maximum number of tokens the LLM should generate in its response (default: `8192`). Adjust this based on your LLM's capabilities and desired checklist detail.
        *   **Batch Size:** The number of HTTP interactions to send to the LLM for analysis in each batch (default: `2`). Adjust this based on the complexity of your target application and the context window of your LLM. A smaller batch size might be more reliable for LLMs with smaller context windows.
    *   Click **"Save"** to apply your settings or **"Cancel"** to discard changes.

4.  **Generate Checklist:**
    *   Once a domain is selected, click the **"Generate Checklist"** button.
    *   The extension will begin processing the HTTP history for the selected domain in batches.
    *   A progress bar and status updates will be displayed in the **"Progress"** panel.

5.  **Review Results:**
    *   The results will be displayed in two tabs:
        *   **"Batch Results"**: This tab shows a list of the batches processed. Selecting a batch from the list on the left will display the raw checklist generated by the LLM for that specific batch on the right. The content is rendered as HTML using Markdown for better readability.
        *   **"Consolidated Checklist"**: This tab displays the final, consolidated penetration testing checklist generated by the LLM after analyzing all batches. This aims to provide a comprehensive and de-duplicated list of testing points. The content is also rendered as HTML using Markdown.

6.  **Control Processing:**
    *   **"Stop"**: If the checklist generation is taking too long or you need to interrupt it, click the **"Stop"** button. The current progress will be halted.
    *   **"Resume"**: If the processing was stopped, the **"Resume"** button will be enabled. Clicking it will attempt to continue the checklist generation from where it was interrupted.

7.  **Save Checklist:**
    *   To save the generated consolidated checklist to a file, click the **"Save Checklist"** button.
    *   A file dialog will appear, allowing you to choose the save location and filename (default filename includes the domain and a timestamp). The checklist will be saved as a Markdown (`.md`) file.
    *   Individual batch checklists are also saved in a subdirectory named `batches_[timestamp]` within the same directory where you save the consolidated checklist.

8.  **Clear Results:**
    *   To clear the currently displayed checklists and prepare for a new analysis, click the **"Clear Results"** button.

9.  **Using Context Menu:**
    *   In any Burp Suite view (e.g., HTTP history, Proxy intercept), you can right-click on an HTTP request.
    *   Select **"Set as Target for Pentest"**. This will automatically select the domain of the clicked request in the "Select Domain" dropdown in the "Pentest Checklist" tab.
  
## Acknowledgements
*   The developers of Ollama and the underlying Large Language Models for making local LLM inference accessible.
