# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IScannerCheck, IHttpListener, IContextMenuFactory
from javax.swing import JPanel, JButton, JTextArea, JEditorPane, JScrollPane, JComboBox, JLabel, JTextField, BoxLayout, JOptionPane
from javax.swing import JFileChooser, JSplitPane, JTabbedPane, JProgressBar, SwingConstants, JTable, JTextPane, DefaultListModel, JList
from javax.swing import JDialog, JFrame, WindowConstants, SwingUtilities, ImageIcon
from javax.swing.border import EmptyBorder, TitledBorder
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, Dimension, Font, Color, GridLayout, GridBagLayout, GridBagConstraints
import javax.swing.SwingWorker as SwingWorker
from java.util import ArrayList
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from java.io import File, FileWriter
import json
import time
import urllib2
import base64
import datetime
import xml.etree.ElementTree as ET
from threading import Lock
import markdown
import os
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

# Configuration constants - these will now be configurable
DEFAULT_API_ENDPOINT = "http://localhost:11434/api/generate"  # Ollama endpoint
DEFAULT_MAX_TOKENS = 8192
OLLAMA_MODEL = "hf.co/unsloth/gemma-3-27b-it-GGUF:Q4_K_M"
DEFAULT_BATCH_SIZE = 2

class SettingsDialog(JDialog):
    def __init__(self, parent_component, current_settings):
        JDialog.__init__(self, SwingUtilities.getWindowAncestor(parent_component), "Settings", True)
        self.current_settings = current_settings
        self.result = None
        self.setSize(500, 300)
        self.setLocationRelativeTo(parent_component)
        self.initComponents()
        
    def initComponents(self):
        mainPanel = JPanel(BorderLayout(10, 10))
        mainPanel.setBorder(EmptyBorder(15, 15, 15, 15))
        
        # Create settings panel
        settingsPanel = JPanel(GridLayout(0, 2, 10, 10))
        settingsPanel.setBorder(TitledBorder("Ollama API Settings"))
        
        # API Endpoint
        settingsPanel.add(JLabel("API Endpoint:"))
        self.apiEndpointField = JTextField(self.current_settings.get("api_endpoint", DEFAULT_API_ENDPOINT))
        settingsPanel.add(self.apiEndpointField)
        
        # Model Name
        settingsPanel.add(JLabel("Model Name:"))
        self.modelNameField = JTextField(self.current_settings.get("model", OLLAMA_MODEL))
        settingsPanel.add(self.modelNameField)
        
        # Max Tokens
        settingsPanel.add(JLabel("Max Tokens:"))
        self.maxTokensField = JTextField(str(self.current_settings.get("max_tokens", DEFAULT_MAX_TOKENS)))
        settingsPanel.add(self.maxTokensField)
        
        # Batch Size
        settingsPanel.add(JLabel("Batch Size:"))
        self.batchSizeField = JTextField(str(self.current_settings.get("batch_size", DEFAULT_BATCH_SIZE)))
        settingsPanel.add(self.batchSizeField)
        
        mainPanel.add(settingsPanel, BorderLayout.CENTER)
        
        # Create buttons panel
        buttonsPanel = JPanel()
        saveButton = JButton("Save")
        cancelButton = JButton("Cancel")
        
        class SaveButtonListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                try:
                    # Validate input
                    max_tokens = int(self.outer.maxTokensField.getText())
                    batch_size = int(self.outer.batchSizeField.getText())
                    
                    # Save settings
                    self.outer.result = {
                        "api_endpoint": self.outer.apiEndpointField.getText(),
                        "model": self.outer.modelNameField.getText(),
                        "max_tokens": max_tokens,
                        "batch_size": batch_size
                    }
                    self.outer.dispose()
                except ValueError:
                    JOptionPane.showMessageDialog(self.outer, "Invalid numeric values. Please check your input.", 
                                                "Input Error", JOptionPane.ERROR_MESSAGE)
        
        class CancelButtonListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                self.outer.dispose()
        
        saveButton.addActionListener(SaveButtonListener(self))
        cancelButton.addActionListener(CancelButtonListener(self))
        
        buttonsPanel.add(saveButton)
        buttonsPanel.add(cancelButton)
        
        mainPanel.add(buttonsPanel, BorderLayout.SOUTH)
        self.setContentPane(mainPanel)
        self.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._api_key = ""
        self._lock = Lock()
        
        # Initialize the settings
        self._settings = {
            "api_endpoint": DEFAULT_API_ENDPOINT,
            "model": OLLAMA_MODEL,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "batch_size": DEFAULT_BATCH_SIZE
        }
        
        # Set the extension name
        callbacks.setExtensionName("Pentest Checklist Generator")
        # Register ourselves as an HTTP listener and context menu factory
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        # Initialize UI components
        self._setupUI()
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        # Initialize data structures
        self._http_history = []
        self._selected_domain = ""
        self._pentest_checklist = ""
        self._checklist_batches = {}  # To store individual batch results
        self._processingCancelled = False
        self._processingPaused = False
        self._currentWorker = None
        self._resumeState = None
        print("Pentest Checklist Generator loaded successfully!")

    def _setupUI(self):
        # Create main panel
        self._mainPanel = JPanel(BorderLayout())
        # Create tabbed pane for multiple views
        self._tabbedPane = JTabbedPane()
        
        # Create control panel (top)
        controlPanel = JPanel()
        controlPanel.setLayout(BoxLayout(controlPanel, BoxLayout.Y_AXIS))
        controlPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        # Create header panel with title and settings button
        headerPanel = JPanel(BorderLayout(10, 0))
        
        # Title label
        titleLabel = JLabel("Pentest Checklist Generator")
        titleLabel.setFont(Font("Sans Serif", Font.BOLD, 16))
        headerPanel.add(titleLabel, BorderLayout.CENTER)
        
        # Settings button
        settingsButton = JButton(u"⚙️")
        # Make button smaller and more icon-like
        #settingsButton.setPreferredSize(Dimension(50, 40))
        settingsButton.setFocusPainted(False)
        
        class SettingsButtonListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                dialog = SettingsDialog(self.outer._mainPanel, self.outer._settings)
                dialog.setVisible(True)
                if dialog.result:
                    self.outer._settings = dialog.result
                    self.outer.updateProgress("Settings updated successfully", 100)
        
        settingsButton.addActionListener(SettingsButtonListener(self))
        headerPanel.add(settingsButton, BorderLayout.EAST)
        
        # Add header panel to control panel
        controlPanel.add(headerPanel)
        
        # Create progress panel with progress bar
        progressPanel = JPanel(BorderLayout())
        progressPanel.setBorder(TitledBorder("Progress"))
        
        # Create a sub-panel for the progress bar and buttons
        progressBarPanel = JPanel(BorderLayout())
        self._progressBar = JProgressBar(0, 100)
        self._progressBar.setStringPainted(True)
        self._progressBar.setString("Ready")
        progressBarPanel.add(self._progressBar, BorderLayout.CENTER)
        
        # Create control buttons panel
        controlButtonsPanel = JPanel()
        self._stopButton = JButton("Stop")
        self._resumeButton = JButton("Resume")
        self._resumeButton.setEnabled(False)  # Initially disabled
        controlButtonsPanel.add(self._stopButton)
        controlButtonsPanel.add(self._resumeButton)
        
        # Add action listeners for the buttons
        class StopButtonListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                self.outer._stopProcessing()
        
        class ResumeButtonListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                self.outer._resumeProcessing()
        
        self._stopButton.addActionListener(StopButtonListener(self))
        self._resumeButton.addActionListener(ResumeButtonListener(self))
        
        progressBarPanel.add(controlButtonsPanel, BorderLayout.EAST)
        progressPanel.add(progressBarPanel, BorderLayout.NORTH)
        
        self._progressStatusLabel = JLabel("Status: Ready")
        self._progressStatusLabel.setFont(Font("Sans Serif", Font.PLAIN, 12))
        progressPanel.add(self._progressStatusLabel, BorderLayout.CENTER)
        
        # Domain selection and checklist generation
        domainPanel = JPanel()
        domainPanel.setLayout(BoxLayout(domainPanel, BoxLayout.X_AXIS))
        domainPanel.setBorder(EmptyBorder(5, 0, 5, 0))
        
        domainLabel = JLabel("Select Domain: ")
        self._domainComboBox = JComboBox()
        refreshDomainsButton = JButton("Refresh Domains")
        generateButton = JButton("Generate Checklist")
        
        # Make the generate button stand out
        generateButton.setBackground(Color(0, 120, 215))
        generateButton.setForeground(Color.WHITE)
        
        class RefreshDomainsListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                self.outer.updateProgress("Refreshing domains...", 0)
                self.outer._populateDomains()
        
        class GenerateChecklistListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                self.outer.updateProgress("Preparing to generate checklist...", 0)
                self.outer._generateChecklist()
        
        class SaveChecklistListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                self.outer._saveChecklistToFile()
        
        refreshDomainsButton.addActionListener(RefreshDomainsListener(self))
        generateButton.addActionListener(GenerateChecklistListener(self))
        
        domainPanel.add(domainLabel)
        domainPanel.add(self._domainComboBox)
        domainPanel.add(refreshDomainsButton)
        domainPanel.add(generateButton)
        
        # Action buttons panel (Save/Clear)
        actionsPanel = JPanel()
        actionsPanel.setLayout(BoxLayout(actionsPanel, BoxLayout.X_AXIS))
        actionsPanel.setBorder(EmptyBorder(5, 0, 0, 0))
        
        saveButton = JButton("Save Checklist")
        clearButton = JButton("Clear Results")
        
        class ClearResultsListener(ActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                self.outer._resultTextPane.setText("")
                self.outer._consolidatedPane.setText("")
                self.outer._pentest_checklist = ""
                self.outer._checklist_batches.clear()
                self.outer._batchListModel.clear()
                self.outer.updateProgress("Results cleared", 0)
        
        clearButton.addActionListener(ClearResultsListener(self))
        saveButton.addActionListener(SaveChecklistListener(self))
        
        actionsPanel.add(saveButton)
        actionsPanel.add(clearButton)
        
        # Add panels to control panel
        controlPanel.add(progressPanel)
        controlPanel.add(domainPanel)
        controlPanel.add(actionsPanel)
        
        # Create results tabs
        self._resultTabsPanel = JPanel(BorderLayout())
        
        # Create a split pane for batch list and content
        self._splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Create batch list panel
        batchListPanel = JPanel(BorderLayout())
        batchListPanel.setBorder(TitledBorder("Batches"))
        self._batchListModel = DefaultListModel()
        self._batchList = JList(self._batchListModel)
        
        # Implement the correct ListSelectionListener interface
        class BatchSelectionListener(ListSelectionListener):
            def __init__(self, outer):
                self.outer = outer
            def valueChanged(self, event):
                if not event.getValueIsAdjusting():  # Only process when selection is final
                    selected = self.outer._batchList.getSelectedValue()
                    if selected:
                        content = self.outer._checklist_batches.get(selected, "")
                        self.outer._resultTextPane.setText(markdown.markdown(content))
        
        # Add the correct listener
        self._batchList.addListSelectionListener(BatchSelectionListener(self))
        batchListPanel.add(JScrollPane(self._batchList), BorderLayout.CENTER)
        
        # Create result text pane (for HTML display)
        self._resultTextPane = JEditorPane("text/html", "")
        self._resultTextPane.setEditable(False)
        self._resultTextPane.setContentType("text/html")
        resultScrollPane = JScrollPane(self._resultTextPane)
        
        # Add components to split pane
        self._splitPane.setLeftComponent(batchListPanel)
        self._splitPane.setRightComponent(resultScrollPane)
        self._splitPane.setDividerLocation(200)  # Set initial divider position
        
        # Add split pane to results panel
        self._resultTabsPanel.add(self._splitPane, BorderLayout.CENTER)
        
        # Create consolidated view tab
        self._consolidatedPane = JEditorPane("text/html", "")
        self._consolidatedPane.setEditable(False)
        self._consolidatedPane.setContentType("text/html")
        consolidatedScrollPane = JScrollPane(self._consolidatedPane)
        
        # Add tabs to tabbed pane
        self._tabbedPane.addTab("Batch Results", self._resultTabsPanel)
        self._tabbedPane.addTab("Consolidated Checklist", consolidatedScrollPane)
        
        # Add panels to main panel
        self._mainPanel.add(controlPanel, BorderLayout.NORTH)
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)

    def _stopProcessing(self):
        """Stop the current processing"""
        self._processingCancelled = True
        self.updateProgress("Processing stopped by user", 0)
        self._stopButton.setEnabled(False)
        self._resumeButton.setEnabled(True)

    def _resumeProcessing(self):
        """Resume the previously stopped processing"""
        if self._resumeState:
            self._processingCancelled = False
            self._resumeButton.setEnabled(False)
            self._stopButton.setEnabled(True)
            # Extract saved state
            domain = self._resumeState.get("domain")
            http_history = self._resumeState.get("http_history")
            processed_count = self._resumeState.get("processed_count", 0)
            batch_size = self._resumeState.get("batch_size")
            combined_checklist = self._resumeState.get("combined_checklist", "")
            
            # Start a new worker to continue processing
            class ResumeWorker(SwingWorker):
                def __init__(self, outer, state):
                    self.outer = outer
                    self.state = state
                
                def doInBackground(self):
                    return self.outer._resumeProcessSelectedDomain(
                        self.state["domain"],
                        self.state["http_history"],
                        self.state["processed_count"],
                        self.state["batch_size"],
                        self.state["combined_checklist"]
                    )
                
                def done(self):
                    try:
                        if not self.outer._processingCancelled:
                            result = self.get()
                            # Update consolidated view
                            html_content = markdown.markdown(result)
                            self.outer._consolidatedPane.setText(html_content)
                            # Switch to the consolidated view tab
                            self.outer._tabbedPane.setSelectedIndex(1)
                            self.outer._pentest_checklist = result
                            self.outer.updateProgress("Checklist generation complete!", 100)
                    except Exception as e:
                        error_msg = "Error in ResumeWorker.done: " + str(e)
                        self.outer.updateProgress(error_msg, 0)
            
            worker = ResumeWorker(self, self._resumeState)
            self._currentWorker = worker
            worker.execute()
            self.updateProgress("Resuming processing from batch " + str(processed_count), -1)
        else:
            self.updateProgress("No processing state to resume", 0)
            self._resumeButton.setEnabled(False)

    def _resumeProcessSelectedDomain(self, domain, http_history, processed_count, batch_size, combined_checklist):
        """Continue processing from where it was stopped"""
        #batch_sizes = self._settings.get("batch_size", DEFAULT_BATCH_SIZE)
        try:
            self._processingCancelled = False
            total_items = len(http_history)
            # Skip already processed items
            batch_progress_start = 35
            batch_progress_end = 85
            progress_per_batch = float(batch_progress_end - batch_progress_start) / max(1, (total_items / batch_size))
            
            # Continue processing batches from where we left off
            for i in range(processed_count, total_items, batch_size):
                # Check if processing was cancelled
                if self._processingCancelled:
                    # Save state for potential resume
                    self._resumeState = {
                        "domain": domain,
                        "http_history": http_history,
                        "processed_count": i,
                        "batch_size": batch_size,
                        "combined_checklist": combined_checklist
                    }
                    return combined_checklist
                
                batch = http_history[i:i+batch_size]
                processed = i + len(batch)
                
                # Calculate progress percentage
                progress = batch_progress_start + (processed * progress_per_batch / total_items)
                
                # Create batch description
                batch_description = "Batch {0}-{1} of {2}".format(
                    i+1, min(i+batch_size, total_items), total_items
                )
                
                # Create XML for this batch
                xml_data = self._createXmlData(batch)
                
                # Update progress with more detailed status
                self.updateProgress("Processing " + batch_description +
                                   " ({0:.1f}%)".format(processed * 100.0 / total_items),
                                   int(progress))
                
                # Send to Ollama API
                checklist_result = self._sendToOllama(xml_data, batch_description)
                
                # Add batch to list and store result
                batch_key = batch_description
                self._batchListModel.addElement(batch_key)
                self._checklist_batches[batch_key] = checklist_result
                
                # Add to combined results
                combined_checklist += "# " + batch_description + " CHECKLIST\n\n"
                combined_checklist += checklist_result + "\n\n"
                
                # Sleep to avoid rate limiting
                time.sleep(1)
                
            # Continue with the rest of the processing as before
            # Generate final consolidated checklist
            self.updateProgress("Generating final consolidated checklist...", 90)
            max_tokens = self._settings.get("max_tokens", DEFAULT_MAX_TOKENS)
            max_chunk_size = max_tokens
            chunks = [combined_checklist[i:i + max_chunk_size] for i in range(0, len(combined_checklist), max_chunk_size)]
            consolidated_checklist_parts = []
            
            for i, chunk in enumerate(chunks):
                # Check if processing was cancelled
                if self._processingCancelled:
                    # Save state for potential resume, but at this point we're in consolidation
                    self._resumeState = {
                        "domain": domain,
                        "http_history": http_history,
                        "processed_count": total_items,  # We've processed all batches
                        "batch_size": batch_size,
                        "combined_checklist": combined_checklist,
                        "consolidation_index": i,
                        "consolidated_parts": consolidated_checklist_parts
                    }
                    return combined_checklist
                
                self.updateProgress("Processing consolidated chunk " + str(i+1) + " of " + str(len(chunks)),
                                   90 + (i * 5 / len(chunks)))
                
                final_prompt = ("You've analyzed a website at domain '{0}' in batches. Based on the analysis you've done, " +
                               "generate a final, consolidated penetration testing checklist that covers all vulnerabilities " +
                               "and testing cases. You must include endpoints, parameters and sample values to be tested. " +
                               "Organize it by vulnerability categories and remove duplicates. Make it detailed and actionable. " +
                               "Here are the analysis you have done (chunk {1} of {2}): '{3}'").format(
                                   domain, i + 1, len(chunks), chunk)
                                   
                consolidated_checklist_part = self._callOllamaAPI(final_prompt, "Consolidated chunk {0}/{1}".format(i+1, len(chunks)))
                consolidated_checklist_parts.append(consolidated_checklist_part)
                
            consolidated_checklist = "\n\n".join(consolidated_checklist_parts)
            
            # Store consolidated checklist
            self._batchListModel.addElement("Consolidated Checklist")
            self._checklist_batches["Consolidated Checklist"] = consolidated_checklist
            
            # Combine all results
            full_result = "# PENETRATION TESTING CHECKLIST FOR: {0}\n\n".format(domain)
            full_result += "## CONSOLIDATED CHECKLIST\n\n"
            full_result += consolidated_checklist + "\n\n"
            full_result += "## DETAILED BATCH ANALYSIS\n\n"
            full_result += combined_checklist
            
            self.updateProgress("Checklist generation complete!", 100)
            
            # Save the checklist automatically
            try:
                self._pentest_checklist = full_result
                self._saveChecklistToFile(silent=True)
            except Exception as e:
                self.updateProgress("Error saving checklist: " + str(e), 0)
                
            return full_result
            
        except Exception as e:
            error_msg = "Error in _resumeProcessSelectedDomain: " + str(e)
            self.updateProgress(error_msg, 0)
            return "Error processing domain: " + str(e)

    def updateProgress(self, message, percentage):
        """Update the progress bar and status message"""
        # Import required Java classes
        from javax.swing import SwingUtilities
        
        # Define a simple function to update the UI
        def updateUI():
            self._progressStatusLabel.setText("Status: " + message)
            if percentage >= 0:  # Only update percentage if it's a valid value
                self._progressBar.setValue(percentage)
                self._progressBar.setString(str(percentage) + "%")
                self._progressBar.setIndeterminate(False)
            else:
                # Indeterminate progress
                self._progressBar.setIndeterminate(True)
                self._progressBar.setString(message)
                
            # Force UI refresh
            self._progressStatusLabel.repaint()
            self._progressBar.repaint()
            
        # Execute update on the Event Dispatch Thread
        SwingUtilities.invokeLater(updateUI)
        print(message)  # Also print to console for debugging

    def _populateDomains(self):
        """Populate the domain combo box with domains from Burp's site map"""
        try:
            self._domainComboBox.removeAllItems()
            # Get domains from sitemap
            sitemap = self._callbacks.getSiteMap(None)
            domains = set()
            
            for item in sitemap:
                request = item.getRequest()
                if request is not None:
                    reqInfo = self._helpers.analyzeRequest(item)
                    url = reqInfo.getUrl()
                    domain = url.getHost()
                    if domain and domain not in domains:
                        domains.add(domain)
                        self._domainComboBox.addItem(domain)
                        
            if self._domainComboBox.getItemCount() > 0:
                self._domainComboBox.setSelectedIndex(0)
                
            self.updateProgress("Domains populated: " + str(len(domains)) + " domains found", 100)
            
        except Exception as e:
            error_msg = "Error in _populateDomains: " + str(e)
            self.updateProgress(error_msg, 0)
            JOptionPane.showMessageDialog(self._mainPanel, error_msg)

    def _generateChecklist(self):
        """Generate a penetration testing checklist for the selected domain"""
        try:
            selected_domain = self._domainComboBox.getSelectedItem()
            if not selected_domain:
                JOptionPane.showMessageDialog(self._mainPanel, "Please select a domain first!")
                return
                
            # Clear previous results
            self._resultTextPane.setText("")
            self._batchListModel.clear()
            self._checklist_batches.clear()
            self._pentest_checklist = ""
            
            # Show progress message
            self.updateProgress("Generating checklist for domain: " + selected_domain, 5)
            self._resultTextPane.setText("<html><body><h2>Generating checklist for domain: " +
                                         selected_domain + "</h2><p>This may take a while depending on the size of the sitemap...</p></body></html>")
            
            # Use SwingWorker to prevent UI freezing
            class ChecklistWorker(SwingWorker):
                def __init__(self, outer, domain):
                    self.outer = outer
                    self.domain = domain
                
                def doInBackground(self):
                    return self.outer._processSelectedDomain(self.domain)
                
                def done(self):
                    try:
                        result = self.get()
                        # Update consolidated view
                        html_content = markdown.markdown(result)
                        self.outer._consolidatedPane.setText(html_content)
                        # Switch to the consolidated view tab
                        self.outer._tabbedPane.setSelectedIndex(1)
                        self.outer._pentest_checklist = result
                        self.outer.updateProgress("Checklist generation complete!", 100)
                    except Exception as e:
                        error_msg = "Error in SwingWorker.done: " + str(e)
                        self.outer.updateProgress(error_msg, 0)
                        self.outer._resultTextPane.setText("<html><body><h2>Error</h2><p>" + error_msg + "</p></body></html>")
                        
            worker = ChecklistWorker(self, selected_domain)
            worker.execute()
            
        except Exception as e:
            error_msg = "Error in _generateChecklist: " + str(e)
            self.updateProgress(error_msg, 0)
            JOptionPane.showMessageDialog(self._mainPanel, "Error: " + str(e))

    def _processSelectedDomain(self, domain):
        """Process HTTP history for the selected domain and generate a checklist"""
        try:
            # Reset the cancellation flag when starting a new processing job
            self._processingCancelled = False
            self._stopButton.setEnabled(True)
            self._resumeButton.setEnabled(False)
            
            self.updateProgress("Processing domain: " + domain, 10)
            # Get all requests for the selected domain from the site map
            sitemap = self._callbacks.getSiteMap(None)
            http_history = []
            self.updateProgress("Scanning sitemap for domain: " + domain, 15)
            
            # Collect all requests for the selected domain
            for item in sitemap:
                # Check if processing was cancelled
                if self._processingCancelled:
                    self.updateProgress("Domain scanning cancelled by user", 0)
                    return "Processing cancelled by user"
                    
                request = item.getRequest()
                response = item.getResponse()
                if request is not None and response is not None:
                    req_info = self._helpers.analyzeRequest(item)
                    url = req_info.getUrl()
                    if url.getHost() == domain:
                        # Extract request details
                        req_headers = req_info.getHeaders()
                        req_body = request[req_info.getBodyOffset():]
                        req_method = req_info.getMethod()
                        req_url = str(url)
                        
                        # Extract response details
                        resp_info = self._helpers.analyzeResponse(response)
                        resp_headers = resp_info.getHeaders()
                        resp_body = response[resp_info.getBodyOffset():]
                        resp_status = resp_info.getStatusCode()
                        
                        # Create timestamp
                        timestamp = datetime.datetime.now().isoformat()
                        
                        # Store the HTTP interaction
                        http_history.append({
                            'url': req_url,
                            'method': req_method,
                            'request_headers': req_headers,
                            'request_body': self._helpers.bytesToString(req_body) if req_body else "",
                            'response_status': resp_status,
                            'response_headers': resp_headers,
                            'response_body': self._helpers.bytesToString(resp_body) if resp_body else "",
                            'timestamp': timestamp
                        })
                        
            self.updateProgress("Collected " + str(len(http_history)) + " HTTP interactions for domain " + domain, 20)
            
            # Sort the HTTP history by timestamp
            http_history.sort(key=lambda x: x['timestamp'])
            
            # Handle large sitemaps with batching
            batch_size = self._settings.get("batch_size", DEFAULT_BATCH_SIZE)
                
            # Process in batches and combine results
            combined_checklist = ""
            total_items = len(http_history)
            processed = 0
            
            if total_items == 0:
                return "No HTTP interactions found for domain: " + domain
                
            # Process domain summary first
            self.updateProgress("Creating domain summary...", 25)
            domain_summary = self._createDomainSummary(domain, http_history)
            
            # Check if processing was cancelled
            if self._processingCancelled:
                self._resumeState = {
                    "domain": domain,
                    "http_history": http_history,
                    "processed_count": 0,
                    "batch_size": batch_size,
                    "combined_checklist": ""
                }
                return "Processing cancelled by user"
                
            self.updateProgress("Sending domain summary to Ollama API...", 30)
            summary_checklist = self._sendToOllama(domain_summary, "Domain Summary")
            combined_checklist += "# DOMAIN SUMMARY CHECKLIST\n\n" + summary_checklist + "\n\n"
            
            # Add domain summary to batch list
            self._batchListModel.addElement("Domain Summary")
            self._checklist_batches["Domain Summary"] = summary_checklist
            
            # Update the result pane with the domain summary
            self._resultTextPane.setText(markdown.markdown(summary_checklist))
            
            # Process batches of requests
            batch_progress_start = 35
            batch_progress_end = 85
            progress_per_batch = float(batch_progress_end - batch_progress_start) / max(1, (total_items / batch_size))
            
            for i in range(0, total_items, batch_size):
                # Check if processing was cancelled
                if self._processingCancelled:
                    # Save state for potential resume
                    self._resumeState = {
                        "domain": domain,
                        "http_history": http_history,
                        "processed_count": i,
                        "batch_size": batch_size,
                        "combined_checklist": combined_checklist
                    }
                    return combined_checklist
                    
                batch = http_history[i:i+batch_size]
                processed += len(batch)
                
                # Calculate progress percentage
                progress = batch_progress_start + (processed * progress_per_batch / total_items)
                
                # Create batch description
                batch_description = "Batch {0}-{1} of {2}".format(
                    i+1, min(i+batch_size, total_items), total_items
                )
                
                # Create XML for this batch
                xml_data = self._createXmlData(batch)
                
                # Update progress with more detailed status
                percentage_complete = processed * 100.0 / total_items
                message = "Processing {0} ({1:.1f}%)".format(batch_description, percentage_complete)
                self.updateProgress(message, int(progress))
                
                # Send to Ollama API
                checklist_result = self._sendToOllama(xml_data, batch_description)
                
                # Add batch to list and store result
                batch_key = batch_description
                self._batchListModel.addElement(batch_key)
                self._checklist_batches[batch_key] = checklist_result
                
                # Add to combined results
                combined_checklist += "# " + batch_description + " CHECKLIST\n\n"
                combined_checklist += checklist_result + "\n\n"
                
                # Sleep to avoid rate limiting
                time.sleep(1)
                
            # Generate final consolidated checklist
            self.updateProgress("Generating final consolidated checklist...", 90)
            max_tokens = self._settings.get("max_tokens", DEFAULT_MAX_TOKENS)
            max_chunk_size = max_tokens  # Adjust as needed (Ollama's context limit)
            chunks = [combined_checklist[i:i + max_chunk_size] for i in range(0, len(combined_checklist), max_chunk_size)]
            consolidated_checklist_parts = []
            
            for i, chunk in enumerate(chunks):
                # Check if processing was cancelled
                if self._processingCancelled:
                    # Save state for potential resume, but at this point we're in consolidation
                    self._resumeState = {
                        "domain": domain,
                        "http_history": http_history,
                        "processed_count": total_items,  # We've processed all batches
                        "batch_size": batch_size,
                        "combined_checklist": combined_checklist,
                        "consolidation_index": i,
                        "consolidated_parts": consolidated_checklist_parts
                    }
                    return combined_checklist
                    
                chunk_description = "consolidated chunk {0} of {1}".format(i+1, len(chunks))
                percentage = 90 + (i * 10 / len(chunks))
                message = "Processing {0} ({1:.1f}%)".format(chunk_description, percentage)
                self.updateProgress(message, int(percentage))
                                   
                final_prompt = ("You've analyzed a website at domain '{0}' in batches. Based on the analysis you've done, " +
                              "generate a final, consolidated penetration testing checklist that covers all vulnerabilities " +
                              "and testing cases. You must include endpoints, parameters and sample values to be tested. " +
                              "Organize it by vulnerability categories and remove duplicates. Make it detailed and actionable. " +
                              "Here are the analysis you have done (chunk {1} of {2}): '{3}'").format(
                                  domain, i + 1, len(chunks), chunk)
                                   
                consolidated_checklist_part = self._callOllamaAPI(final_prompt)
                consolidated_checklist_parts.append(consolidated_checklist_part)
                
            consolidated_checklist = "\n\n".join(consolidated_checklist_parts)
            
            # Store consolidated checklist
            self._batchListModel.addElement("Consolidated Checklist")
            self._checklist_batches["Consolidated Checklist"] = consolidated_checklist
            
            # Combine all results
            full_result = "# PENETRATION TESTING CHECKLIST FOR: {0}\n\n".format(domain)
            full_result += "## CONSOLIDATED CHECKLIST\n\n"
            full_result += consolidated_checklist + "\n\n"
            full_result += "## DETAILED BATCH ANALYSIS\n\n"
            full_result += combined_checklist
            
            self.updateProgress("Checklist generation complete!", 100)
            
            # Save the checklist automatically
            try:
                self._pentest_checklist = full_result
                self._saveChecklistToFile(silent=True)
            except Exception as e:
                self.updateProgress("Error saving checklist: " + str(e), 0)
                
            return full_result
            
        except Exception as e:
            error_msg = "Error in _processSelectedDomain: " + str(e)
            self.updateProgress(error_msg, 0)
            return "Error processing domain: " + str(e)

    def _saveChecklistToFile(self, silent=False):
        """Save the checklist to a file"""
        try:
            if not self._pentest_checklist:
                if not silent:
                    JOptionPane.showMessageDialog(self._mainPanel, "No checklist to save!")
                return
            
            selected_domain = self._domainComboBox.getSelectedItem()
            if not selected_domain:
                selected_domain = "unknown"
            
            # Create filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = "checklist_" + str(selected_domain) + "_" + timestamp + ".md"
            
            # Show file chooser if not silent
            if not silent:
                fileChooser = JFileChooser()
                fileChooser.setSelectedFile(File(default_filename))  # Use the imported File class
                result = fileChooser.showSaveDialog(self._mainPanel)
                
                if result != JFileChooser.APPROVE_OPTION:
                    return
                
                file = fileChooser.getSelectedFile()
                filepath = file.getAbsolutePath()
            else:
                # Get user home directory
                home_dir = os.path.expanduser("~")
                pentest_dir = os.path.join(home_dir, "burp_pentests")
                
                # Create directory if it doesn't exist
                if not os.path.exists(pentest_dir):
                    os.makedirs(pentest_dir)
                
                filepath = os.path.join(pentest_dir, default_filename)
            
            # Save the file with UTF-8 encoding
            with open(filepath, 'w') as f:
                # Ensure content is unicode and encode as UTF-8
                content = self._pentest_checklist
                if not isinstance(content, unicode):
                    content = content.decode('utf-8', 'replace')
                f.write(content.encode('utf-8'))
            
            # Also save individual batches
            if self._checklist_batches:
                batches_dir = os.path.join(os.path.dirname(filepath), "batches_" + timestamp)
                if not os.path.exists(batches_dir):
                    os.makedirs(batches_dir)
                
                for batch_name, batch_content in self._checklist_batches.items():
                    safe_name = str(batch_name).replace(" ", "_").replace("/", "_").replace("\\", "_")
                    batch_file = os.path.join(batches_dir, safe_name + ".md")
                    with open(batch_file, 'w') as f:
                        # Ensure batch content is unicode and encode as UTF-8
                        if not isinstance(batch_content, unicode):
                            batch_content = batch_content.decode('utf-8', 'replace')
                        f.write(batch_content.encode('utf-8'))
            
            if not silent:
                JOptionPane.showMessageDialog(self._mainPanel, "Checklist saved to:\n" + filepath)
            else:
                self.updateProgress("Checklist automatically saved to: " + filepath, 100)
                
        except Exception as e:
            error_msg = "Error saving checklist: " + str(e)
            self.updateProgress(error_msg, 0)
            if not silent:
                JOptionPane.showMessageDialog(self._mainPanel, error_msg)

    def _createDomainSummary(self, domain, http_history):
        """Create a summary of the domain for Ollama API"""
        try:
            self.updateProgress("Analyzing domain statistics...", 22)
            
            endpoint_count = {}
            methods = set()
            status_codes = set()
            parameters = set()
            content_types = set()
            unique_urls = set()
            
            # Analyze the HTTP history to gather domain statistics
            for interaction in http_history:
                # Count endpoints
                url = interaction['url']
                path = url.split('?')[0]  # Remove query parameters
                endpoint_count[path] = endpoint_count.get(path, 0) + 1
                
                # Collect HTTP methods
                methods.add(interaction['method'])
                
                # Collect status codes
                status_codes.add(str(interaction['response_status']))
                unique_urls.add(url)
                
                # Collect parameters from URLs
                if '?' in url:
                    query_params = url.split('?')[1].split('&')
                    for param in query_params:
                        if '=' in param:
                            param_name = param.split('=')[0]
                            parameters.add(param_name)
                
                # Check for form parameters in POST requests
                if interaction['method'] == 'POST' and interaction['request_body']:
                    body = interaction['request_body']
                    if '&' in body and '=' in body:  # Simple form data check
                        form_params = body.split('&')
                        for param in form_params:
                            if '=' in param:
                                param_name = param.split('=')[0]
                                parameters.add(param_name)
                
                # Collect content types
                for header in interaction['response_headers']:
                    if header.lower().startswith('content-type:'):
                        content_type = header.split(':', 1)[1].strip()
                        content_types.add(content_type)
            
            self.updateProgress("Creating domain summary report...", 24)
            
            # Create a textual summary
            summary = "Domain Summary for: {0}\n".format(domain)
            summary += "Total Requests: {0}\n".format(len(http_history))
            summary += "Unique Endpoints: {0}\n".format(len(endpoint_count))
            summary += "HTTP Methods Used: {0}\n".format(', '.join(methods))
            summary += "Status Codes: {0}\n".format(', '.join(status_codes))
            summary += "Content Types: {0}\n".format(', '.join(content_types))
            summary += "Parameter Count: {0}\n\n".format(len(parameters))
            
            summary += "Top 5 Endpoints (by frequency):\n"
            sorted_endpoints = sorted(endpoint_count.items(), key=lambda x: x[1], reverse=True)
            for i, (endpoint, count) in enumerate(sorted_endpoints[:5]):
                summary += "{0}. {1} ({2} requests)\n".format(i+1, endpoint, count)
            
            # Add parameters if not too many
            if len(parameters) <= 100:
                summary += "\nParameters Detected:\n"
                for param in sorted(parameters):
                    summary += "- {0}\n".format(param)
            else:
                summary += "\nParameters: {0} unique parameters detected (too many to list)\n".format(len(parameters))
            
            # Add prompt for Ollama
            summary += """
Based on this domain summary, generate a comprehensive penetration testing checklist.
Consider common vulnerabilities for the observed HTTP methods, endpoints, and parameters.
Focus on:
1. Authentication and authorization testing
2. Input validation vulnerabilities
3. Business logic flaws
4. Common web vulnerabilities (XSS, CSRF, SQLi, etc.)
5. API security issues if applicable
Ignore SSL/TLS issues.
"""
            summary += "\nList of all unique URLs on the domain:\n"
            for url in sorted(unique_urls):
                summary += "- {0}\n".format(url)
            
            summary += "\n"
            return summary
        except Exception as e:
            error_msg = "Error creating domain summary: {0}".format(str(e))
            self.updateProgress(error_msg, 0)
            return error_msg

    def _createXmlData(self, http_interactions):
        """Create XML data from HTTP interactions for Ollama API"""
        # Create XML root element
        root = ET.Element("http_interactions")
        
        # Add HTTP interactions
        for interaction in http_interactions:
            # Create interaction element
            interaction_elem = ET.SubElement(root, "interaction")
            
            # Add URL
            url_elem = ET.SubElement(interaction_elem, "url")
            url_elem.text = interaction['url']
            
            # Add method
            method_elem = ET.SubElement(interaction_elem, "method")
            method_elem.text = interaction['method']
            
            # Add request headers
            req_headers_elem = ET.SubElement(interaction_elem, "request_headers")
            for header in interaction['request_headers']:
                header_elem = ET.SubElement(req_headers_elem, "header")
                header_elem.text = header
            
            # Add request body if not empty
            if interaction['request_body']:
                req_body_elem = ET.SubElement(interaction_elem, "request_body")
                req_body_elem.text = interaction['request_body']
            
            # Add response status
            resp_status_elem = ET.SubElement(interaction_elem, "response_status")
            resp_status_elem.text = str(interaction['response_status'])
            
            # Add response headers
            resp_headers_elem = ET.SubElement(interaction_elem, "response_headers")
            for header in interaction['response_headers']:
                header_elem = ET.SubElement(resp_headers_elem, "header")
                header_elem.text = header
            
            # Add response body if not empty (limit size to avoid XML bloat)
            if interaction['response_body']:
                resp_body = interaction['response_body']
                # Limit response body size to 1000 characters
                if len(resp_body) > 1000:
                    resp_body = resp_body[:1000] + "... [truncated]"
                resp_body_elem = ET.SubElement(interaction_elem, "response_body")
                resp_body_elem.text = resp_body
            
            # Add timestamp
            timestamp_elem = ET.SubElement(interaction_elem, "timestamp")
            timestamp_elem.text = interaction['timestamp']
        
        # Convert to string
        xml_str = ET.tostring(root)
        
        # Add prompt for Ollama
        prompt = """
From the provided XML data (HTTP requests/responses), generate a short penetration testing checklist with specific URLs and payloads. Format each item as: '- test for [vulnerability] [URL] [payload/action]'. Focus only on test cases derived from the provided data.
XML Data:
"""
        return prompt + xml_str

    def _sendToOllama(self, data, batch_description):
        """Send data to Ollama API and get penetration testing checklist"""
        try:
            if self._processingCancelled:
                return "Processing cancelled by user"
            self.updateProgress("Processing " + batch_description, -1)
            
            # Construct the prompt
            prompt = """
You are a cybersecurity expert conducting a web application penetration test.
Below is data from HTTP interactions captured during reconnaissance of a web application.
{0}
Based on this data, create a comprehensive penetration testing checklist.
Your checklist should:
1. Identify potential security vulnerabilities
2. Specify exact test cases with examples where possible
3. Include specific endpoints or parameters to test
4. Provide detailed testing methodologies
5. Be organized by vulnerability categories
6. Be actionable and specific to this application
Format the checklist with clear categories, markdown headers, and bullet points.
""".format(data)
            
            # Call Ollama API
            response = self._callOllamaAPI(prompt, batch_description)
            return response
        except Exception as e:
            error_msg = "Error with Ollama API: {0}".format(str(e))
            self.updateProgress(error_msg, 0)
            return error_msg

    def _callOllamaAPI(self, prompt, description=""):
        """Call the Ollama API with the given prompt"""
        try:
            # Check if processing was cancelled
            if self._processingCancelled:
                return "Processing cancelled by user"
                
            # Get max tokens
            max_tokens = self._settings.get("max_tokens", DEFAULT_MAX_TOKENS)
                
            # Update progress
            message = "Calling Ollama API for " + description if description else "Calling Ollama API"
            self.updateProgress(message, -1)  # -1 means indeterminate progress
            
            # Create request data
            request_data = json.dumps({
                "model": self._settings.get("model", OLLAMA_MODEL),
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": 0.2,
                    "top_p": 0.95,
                    "top_k": 40
                }
            })
            
            # Create request
            req = urllib2.Request(self._settings.get("api_endpoint", DEFAULT_API_ENDPOINT), request_data)
            req.add_header('Content-Type', 'application/json')
            
            # Send request
            wait_message = "Waiting for API response for " + description if description else "Waiting for API response"
            self.updateProgress(wait_message, -1)
            response = urllib2.urlopen(req)
            response_data = response.read()
            
            # Parse response
            response_json = json.loads(response_data)
            
            # Extract response text
            if "response" in response_json:
                success_message = "Response received for " + description if description else "Response received successfully"
                self.updateProgress(success_message, 100 if not description else -1)
                return response_json["response"]
            return "No response text found in API response"
            
        except urllib2.HTTPError as e:
            error_data = e.read()
            try:
                error_json = json.loads(error_data)
                error_message = error_json.get("error", {}).get("message", "Unknown error")
                error_msg = "HTTP Error: {0} - {1}".format(e.code, error_message)
            except:
                error_msg = "HTTP Error: {0} - Unable to parse error response".format(e.code)
            self.updateProgress(error_msg, 0)
            return error_msg
        except Exception as e:
            error_msg = "Error: {0}".format(str(e))
            self.updateProgress(error_msg, 0)
            return error_msg

    # Implement ITab
    def getTabCaption(self):
        return "Pentest Checklist"

    def getUiComponent(self):
        return self._mainPanel

    # Implement IHttpListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We're not using this for live traffic capture in this version
        pass

    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        
        # Add a menu item to set the selected domain
        if invocation.getSelectedMessages() and len(invocation.getSelectedMessages()) == 1:
            message = invocation.getSelectedMessages()[0]
            request = message.getRequest()
            if request is not None:
                req_info = self._helpers.analyzeRequest(message)
                url = req_info.getUrl()
                domain = url.getHost()
                
                class DomainSelectAction(ActionListener):
                    def __init__(self, extender, domain):
                        self.extender = extender
                        self.domain = domain
                    
                    def actionPerformed(self, e):
                        # Find and select the domain in the combo box
                        for i in range(self.extender._domainComboBox.getItemCount()):
                            if self.extender._domainComboBox.getItemAt(i) == self.domain:
                                self.extender._domainComboBox.setSelectedIndex(i)
                                break
                        else:
                            # If domain not found, refresh the list and try again
                            self.extender._populateDomains()
                            for i in range(self.extender._domainComboBox.getItemCount()):
                                if self.extender._domainComboBox.getItemAt(i) == self.domain:
                                    self.extender._domainComboBox.setSelectedIndex(i)
                                    break
                
                action = JButton("Set as Target for Pentest")
                action.addActionListener(DomainSelectAction(self, domain))
                menu_list.add(action)
        
        return menu_list