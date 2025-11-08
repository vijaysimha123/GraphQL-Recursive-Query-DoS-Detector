# -*- coding: utf-8 -*-
# Burp Extension: GraphQL Recursive Query DoS Detector
# Author: Vijaysimha Reddy
# Scans ALL requests regardless of scope

from burp import IBurpExtender, IScannerCheck, IScanIssue, IContextMenuFactory, ITab, IHttpListener
from java.net import URL
from java.io import PrintWriter
from javax.swing import JPanel, JLabel, JTextArea, JScrollPane, BoxLayout, JMenuItem, JButton
from java.awt import Dimension, Component, FlowLayout
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("GraphQL Recursive Query Detector")
        
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Track processed requests to avoid duplicates
        self.processedRequests = set()
        
        # Register scanner, context menu, and HTTP listener
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        
        self.stdout.println("[INIT] Scanner check registered")
        self.stdout.println("[INIT] Context menu registered")
        self.stdout.println("[INIT] HTTP Listener registered - scanning ALL traffic")
        
        # Create UI
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        
        # Header panel with title and button
        headerPanel = JPanel()
        headerPanel.setLayout(FlowLayout(FlowLayout.LEFT))
        headerPanel.setAlignmentX(Component.LEFT_ALIGNMENT)
        
        # Title
        titleLabel = JLabel("GraphQL Recursive Query Detection Results")
        headerPanel.add(titleLabel)
        
        # Clear button
        clearButton = JButton("Clear Output")
        clearButton.addActionListener(lambda x: self.clearOutput())
        headerPanel.add(clearButton)
        
        self._panel.add(headerPanel)
        
        # Results area
        self.resultsArea = JTextArea(30, 100)
        self.resultsArea.setEditable(False)
        self.resultsArea.setText("Scanning ALL requests through Burp Suite (scope independent)\n\n" +
                                "Right-click on any request and select 'Check GraphQL Recursion' to analyze.\n" +
                                "This extension detects RECURSIVE queries where same fields appear in nested paths.\n" +
                                "=" * 80 + "\n\n")
        resultsScrollPane = JScrollPane(self.resultsArea)
        resultsScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT)
        self._panel.add(resultsScrollPane)
        
        callbacks.addSuiteTab(self)
        
        self.stdout.println("GraphQL Recursive Query Detector loaded successfully!")
        self.stdout.println("Author: Vijaysimha Reddy")
        self.stdout.println("- HTTP Listener: ACTIVE (all traffic)")
        self.stdout.println("- Passive scanning: ACTIVE")
        self.stdout.println("- Right-click menu: Available")
        self.stdout.println("- Detection: Recursive/Circular field references")
        self.stdout.println("- Scope: IGNORING scope, scanning everything")
    
    def getTabCaption(self):
        return "GraphQL Recursion"
    
    def getUiComponent(self):
        return self._panel
    
    def clearOutput(self):
        """Clear the results area"""
        self.resultsArea.setText("Output cleared.\n\n" +
                                "Scanning ALL requests through Burp Suite (scope independent)\n\n" +
                                "Right-click on any request and select 'Check GraphQL Recursion' to analyze.\n" +
                                "This extension detects RECURSIVE queries where same fields appear in nested paths.\n" +
                                "=" * 80 + "\n\n")
        self.stdout.println("[UI] Output cleared by user")
    
    def getRequestHash(self, request):
        """Generate a unique hash for the request to avoid duplicates"""
        import hashlib
        requestStr = request.tostring()
        return hashlib.md5(requestStr).hexdigest()
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process all HTTP messages through Burp - scans everything regardless of scope"""
        
        # Only process requests (not responses)
        if not messageIsRequest:
            return
        
        try:
            request = messageInfo.getRequest()
            if request is None:
                return
            
            analyzedRequest = self._helpers.analyzeRequest(messageInfo)
            url = analyzedRequest.getUrl()
            
            # Check if it's a GraphQL request
            if not self.isGraphQLRequest(request, analyzedRequest):
                return
            
            # Generate hash to avoid duplicate processing
            requestHash = self.getRequestHash(request)
            
            # Skip if already processed recently (within same session)
            if requestHash in self.processedRequests:
                return
            
            self.stdout.println("[HTTP LISTENER] Found GraphQL request: " + str(url))
            
            # Extract request body
            bodyOffset = analyzedRequest.getBodyOffset()
            requestBody = request[bodyOffset:].tostring()
            
            # Check for recursive queries
            recursionDepth, recursiveFields = self.detectNestedQueries(requestBody)
            
            if recursionDepth >= 2:
                # Mark as processed before adding issue
                self.processedRequests.add(requestHash)
                
                self.stdout.println("[HTTP LISTENER] Recursive query detected! Depth: " + str(recursionDepth))
                
                # Create and add issue
                issue = CustomScanIssue(
                    messageInfo.getHttpService(),
                    url,
                    [self._callbacks.applyMarkers(messageInfo, None, None)],
                    "GraphQL Recursive Query DoS Vulnerability",
                    "The application accepts recursive/circular GraphQL queries where the same field(s) appear " +
                    str(recursionDepth) + " times in nested paths. " +
                    "This allows an attacker to perform Denial of Service by creating infinite resolution loops " +
                    "that consume excessive server resources.<br><br>" +
                    "<b>Recursive Fields:</b> " + ", ".join(recursiveFields) + "<br>" +
                    "<b>Recursion Depth:</b> " + str(recursionDepth) + " levels<br>" +
                    "<b>Attack Vector:</b> Same field referenced within itself, causing exponential resource consumption.",
                    "Medium",
                    "Certain"
                )
                
                self._callbacks.addScanIssue(issue)
                
                self.stdout.println("[!] Added vulnerability issue for: " + str(url) + 
                                  " (Depth: " + str(recursionDepth) + ", Fields: " + ", ".join(recursiveFields) + ")")
                
                # Log to UI
                self.resultsArea.append("\n[AUTO-SCAN] Found vulnerable request:\n")
                self.resultsArea.append("URL: " + str(url) + "\n")
                self.resultsArea.append("Recursion Depth: " + str(recursionDepth) + "\n")
                self.resultsArea.append("Recursive Fields: " + ", ".join(recursiveFields) + "\n")
                self.resultsArea.append("-" * 80 + "\n")
                
                # Scroll to bottom
                self.resultsArea.setCaretPosition(self.resultsArea.getDocument().getLength())
            else:
                self.stdout.println("[HTTP LISTENER] No recursion detected for: " + str(url))
                
        except Exception as e:
            self.stderr.println("[ERROR] Error in HTTP listener: " + str(e))
            import traceback
            traceback.print_exc(file=self.stderr)
    
    def createMenuItems(self, invocation):
        """Create context menu item"""
        menu = ArrayList()
        
        # Only show menu for requests
        if invocation.getSelectedMessages():
            menuItem = JMenuItem("Check GraphQL Recursion")
            menuItem.addActionListener(lambda x: self.checkSelectedRequests(invocation))
            menu.add(menuItem)
        
        return menu
    
    def checkSelectedRequests(self, invocation):
        """Check selected requests for GraphQL recursion"""
        messages = invocation.getSelectedMessages()
        
        for message in messages:
            request = message.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(message)
            url = analyzedRequest.getUrl()
            
            # Generate hash to check if already processed
            requestHash = self.getRequestHash(request)
            
            # Extract request body
            bodyOffset = analyzedRequest.getBodyOffset()
            requestBody = request[bodyOffset:].tostring()
            
            # Check for recursive queries
            recursionDepth, recursiveFields = self.detectNestedQueries(requestBody)
            
            # Log results
            self.resultsArea.append("\n" + "=" * 80 + "\n")
            self.resultsArea.append("URL: " + str(url) + "\n")
            
            if recursionDepth >= 2:
                self.resultsArea.append("RECURSIVE QUERY DETECTED!\n")
                self.resultsArea.append("Recursion Depth: " + str(recursionDepth) + "\n")
                self.resultsArea.append("Recursive Fields: " + ", ".join(recursiveFields) + "\n")
                self.resultsArea.append("Status: VULNERABLE - Circular field references detected\n")
                self.resultsArea.append("Risk: Can cause infinite loops and DoS\n")
                
                # Only add issue if not already processed
                if requestHash not in self.processedRequests:
                    # Mark as processed
                    self.processedRequests.add(requestHash)
                    
                    # ADD ISSUE TO BURP
                    issue = CustomScanIssue(
                        message.getHttpService(),
                        url,
                        [self._callbacks.applyMarkers(message, None, None)],
                        "GraphQL Recursive Query DoS Vulnerability",
                        "The application accepts recursive/circular GraphQL queries where the same field(s) appear " +
                        str(recursionDepth) + " times in nested paths. " +
                        "This allows an attacker to perform Denial of Service by creating infinite resolution loops " +
                        "that consume excessive server resources.<br><br>" +
                        "<b>Recursive Fields:</b> " + ", ".join(recursiveFields) + "<br>" +
                        "<b>Recursion Depth:</b> " + str(recursionDepth) + " levels<br>" +
                        "<b>Attack Vector:</b> Same field referenced within itself, causing exponential resource consumption.",
                        "Medium",
                        "Certain"
                    )
                    
                    self._callbacks.addScanIssue(issue)
                    self.stdout.println("[MANUAL SCAN] Added issue to Burp for: " + str(url))
                else:
                    self.resultsArea.append("Note: Issue already reported for this request\n")
                    self.stdout.println("[MANUAL SCAN] Skipping duplicate issue for: " + str(url))
                
            elif recursionDepth == 0:
                self.resultsArea.append("Status: OK - No recursive patterns detected\n")
            else:
                self.resultsArea.append("Status: OK - Normal nesting, no recursion\n")
            
            self.resultsArea.append("=" * 80 + "\n")
            
            # Scroll to bottom
            self.resultsArea.setCaretPosition(self.resultsArea.getDocument().getLength())
    
    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning - still available but HTTP listener handles most cases"""
        issues = []
        
        try:
            request = baseRequestResponse.getRequest()
            if request is None:
                return issues
            
            # Generate hash to check for duplicates
            requestHash = self.getRequestHash(request)
            
            # Skip if already processed
            if requestHash in self.processedRequests:
                return issues
            
            analyzedRequest = self._helpers.analyzeRequest(baseRequestResponse)
            url = analyzedRequest.getUrl()
            
            # Check if it's a GraphQL request
            if not self.isGraphQLRequest(request, analyzedRequest):
                return issues
            
            # Extract request body
            bodyOffset = analyzedRequest.getBodyOffset()
            requestBody = request[bodyOffset:].tostring()
            
            # Check for recursive queries
            recursionDepth, recursiveFields = self.detectNestedQueries(requestBody)
            
            if recursionDepth >= 2:
                # Mark as processed
                self.processedRequests.add(requestHash)
                
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    url,
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "GraphQL Recursive Query DoS Vulnerability",
                    "The application accepts recursive/circular GraphQL queries where the same field(s) appear " +
                    str(recursionDepth) + " times in nested paths. " +
                    "This allows an attacker to perform Denial of Service by creating infinite resolution loops " +
                    "that consume excessive server resources.<br><br>" +
                    "<b>Recursive Fields:</b> " + ", ".join(recursiveFields) + "<br>" +
                    "<b>Recursion Depth:</b> " + str(recursionDepth) + " levels<br>" +
                    "<b>Attack Vector:</b> Same field referenced within itself, causing exponential resource consumption.",
                    "Medium",
                    "Certain"
                ))
                
                self.stdout.println("[PASSIVE SCAN] Found recursive GraphQL query at: " + str(url))
        
        except Exception as e:
            self.stderr.println("[ERROR] Error in passive scan: " + str(e))
        
        return issues
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """No active scanning"""
        return []
    
    def isGraphQLRequest(self, request, analyzedRequest):
        """Check if request is a GraphQL request"""
        
        # Get path and body
        url = analyzedRequest.getUrl().getPath().lower()
        bodyOffset = analyzedRequest.getBodyOffset()
        requestBody = request[bodyOffset:].tostring() if bodyOffset < len(request) else ""
        
        # Check URL path - common GraphQL endpoints
        if "/graphql" in url or "/graph" in url or "/gql" in url:
            if requestBody and ("query" in requestBody.lower() or "mutation" in requestBody.lower()):
                return True
        
        # Check Content-Type header
        headers = analyzedRequest.getHeaders()
        for header in headers:
            if "content-type" in header.lower() and "application/json" in header.lower():
                # JSON with GraphQL keywords
                if requestBody and ("query" in requestBody.lower() or "mutation" in requestBody.lower() or "subscription" in requestBody.lower()):
                    return True
        
        return False
    
    def detectNestedQueries(self, requestBody):
        """Detect recursive/circular nesting in GraphQL queries"""
        
        try:
            # Extract query
            query = self.extractGraphQLQuery(requestBody)
            
            if not query:
                return (0, [])
            
            # Check for circular/recursive patterns
            recursionDepth, recursiveFields = self.detectCircularNesting(query)
            
            return (recursionDepth, recursiveFields)
            
        except Exception as e:
            self.stderr.println("Error detecting nested queries: " + str(e))
            return (0, [])
    
    def detectCircularNesting(self, query):
        """Detect if the same field appears recursively in the query - IMPROVED VERSION"""
        
        # Remove comments
        query = re.sub(r'#.*$', '', query, flags=re.MULTILINE)
        
        # Remove strings to avoid processing field values
        query = re.sub(r'"[^"]*"', '', query)
        query = re.sub(r"'[^']*'", '', query)
        
        # Remove query/mutation wrapper keywords and operation names
        query = re.sub(r'\bquery\b\s+\w*\s*', '', query, flags=re.IGNORECASE)
        query = re.sub(r'\bmutation\b\s+\w*\s*', '', query, flags=re.IGNORECASE)
        query = re.sub(r'\bsubscription\b\s+\w*\s*', '', query, flags=re.IGNORECASE)
        
        # Remove arguments (everything between parentheses)
        query = re.sub(r'\([^)]*\)', '', query)
        
        # Remove aliases (field: before field name)
        query = re.sub(r'\w+\s*:\s*', '', query)
        
        # Extract tokens (field names and braces)
        tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*|[{}]', query)
        
        self.stdout.println("[ANALYSIS] Processing query with " + str(len(tokens)) + " tokens")
        
        # Track all field paths to detect recursion
        currentPath = []
        allPaths = []
        maxRecursionDepth = 0
        recursiveFieldsMap = {}
        
        i = 0
        while i < len(tokens):
            token = tokens[i]
            
            if token == '{':
                # Opening brace - entering nested selection
                if i > 0 and tokens[i-1] not in ['{', '}']:
                    fieldName = tokens[i-1]
                    currentPath.append(fieldName)
                    
                    # Store the path
                    pathCopy = list(currentPath)
                    allPaths.append(pathCopy)
                    
                    # Check for recursion in this path
                    fieldCount = currentPath.count(fieldName)
                    if fieldCount > 1:
                        if fieldName not in recursiveFieldsMap:
                            recursiveFieldsMap[fieldName] = fieldCount
                        else:
                            recursiveFieldsMap[fieldName] = max(recursiveFieldsMap[fieldName], fieldCount)
                        
                        maxRecursionDepth = max(maxRecursionDepth, fieldCount)
                        self.stdout.println("[FOUND] Recursion: '" + fieldName + "' appears " + str(fieldCount) + " times in path: " + " -> ".join(currentPath))
            
            elif token == '}':
                # Closing brace - exiting nested selection
                if currentPath:
                    currentPath.pop()
            
            i += 1
        
        recursiveFields = recursiveFieldsMap.keys()
        
        self.stdout.println("[RESULT] Max recursion depth: " + str(maxRecursionDepth))
        self.stdout.println("[RESULT] Recursive fields: " + str(list(recursiveFields)))
        self.stdout.println("[RESULT] Total paths analyzed: " + str(len(allPaths)))
        
        return (maxRecursionDepth, list(recursiveFields))
    
    def extractGraphQLQuery(self, requestBody):
        """Extract GraphQL query from request body"""
        
        import json
        
        try:
            # Try to parse as JSON
            data = json.loads(requestBody)
            
            # Handle different GraphQL request formats
            if isinstance(data, dict):
                if "query" in data:
                    return data["query"]
                elif "mutation" in data:
                    return data["mutation"]
                elif "queries" in data:
                    # Batched queries - check first one
                    queries = data["queries"]
                    if isinstance(queries, list) and len(queries) > 0:
                        return queries[0].get("query", "")
            
            # If not JSON, might be raw GraphQL
            return requestBody
            
        except:
            # Not valid JSON, treat as raw GraphQL query
            return requestBody
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return self._confidence
    
    def getIssueBackground(self):
        return "GraphQL allows clients to request nested data structures. When the same field appears " \
               "recursively in its own nested path, it can create infinite resolution loops. Without proper " \
               "recursion depth limiting, an attacker can craft recursive queries that cause the server to " \
               "perform exponential processing, leading to Denial of Service."
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return "Implement query depth and recursion limiting on the GraphQL server:<br><br>" \
               "1. <b>Depth Limiting:</b><br>" \
               "   - Apollo Server: Use 'graphql-depth-limit' package<br>" \
               "   - Express-GraphQL: Use 'graphql-depth-limit' middleware<br>" \
               "   - Set a reasonable depth limit (e.g., 5-10 levels)<br><br>" \
               "2. <b>Recursion Detection:</b><br>" \
               "   - Track field paths during query execution<br>" \
               "   - Reject queries with circular field references<br>" \
               "   - Limit the number of times a field can appear in its own path<br><br>" \
               "3. <b>Query Complexity Analysis:</b><br>" \
               "   - Implement query cost analysis<br>" \
               "   - Set maximum complexity scores<br>" \
               "   - Consider using persistent queries/query whitelisting for production<br><br>" \
               
    
    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService
