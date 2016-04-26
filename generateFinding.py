# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IExtensionHelpers
from burp import IHttpRequestResponseWithMarkers
from burp import ITab
from burp import IMessageEditorController
from burp import ITextEditor
from burp import IHttpService
from burp import IScanIssue
from array import array
from java.awt import Component, GridLayout
from java.io import PrintWriter
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyEvent
from java.util import List
from javax.swing import (JMenuItem, GroupLayout, JFrame, JSplitPane, JTabbedPane, JPanel, JScrollPane, JTextArea, JTextField, JLabel, JButton, JComboBox)
import java.util.List
import traceback
import pprint
import urllib2

# Burp is configured to look for python modules in c:\python27\lib. 
# If the following file exists in that directory, it will be loaded


# Chenges and updates required:
# Rebuild requestResponse from "Generate Finding" tab
# Pass request response user selection markers to 'Generate Finding' tab so that the markers are viewable
# request used to generate finding should be inscope! code a check use inScope...

# Placeholders
issueNamePlaceholder = " [Template] Insert Finding Name..."
issueDetailPlaceholder = " [Template] Insert Issue Detail...\n\n\n"
issueBackgroundPlaceholder = " [Template] Insert Background Detail...\n\n\n"
remediationDetailPlaceholder = " [Template] Insert Remediation Detail...\n\n\n"
remediationBackgroundPlaceholder = " [Template] Insert Remediation Background...\n\n\n"
issueURLPlaceholder = " [Template] https://www.targetsite.com/img/"
issuePortPlaceholder = " [Template] 443"


class BurpExtender(IBurpExtender, IContextMenuFactory, ActionListener, IMessageEditorController, ITab, ITextEditor, IHttpService, IScanIssue, IHttpRequestResponseWithMarkers):

    def __init__(self):
        self.menuItem = JMenuItem('Generate Finding')
        self.menuItem.addActionListener(self)   

    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks   
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Generate Finding")
        callbacks.registerContextMenuFactory(self)

        # -- Request Response Viewers -- #

        # create the lower half for the Request Response tabs...
        # Request and response from selection
        self._tabbedPane = JTabbedPane()
        tabs = self._tabbedPane
        self._requestViewer = callbacks.createMessageEditor(self, True)
        self._responseViewer = callbacks.createMessageEditor(self, True)
        self._requestHighlight = callbacks.createTextEditor()
        self._responseHighlight = callbacks.createTextEditor()
        tabs.addTab("Supporting Request", self._requestViewer.getComponent())
        tabs.addTab("Supporting Response", self._responseViewer.getComponent())
        tabs.addTab("Request Marker Selection", self._requestHighlight.getComponent())
        tabs.addTab("Response Marker Selection", self._responseHighlight.getComponent())
        #self._mainFrame.setRightComponent(tabs) # set to the lower split pane
        print "*" * 60
        print "[+] Request/Response tabs created"
    

        # -- Define Issue Details GUI & Layout-- #

        # Labels and Input boxes...
        # Issue Name
        self.issueNameLabel = JLabel(" Issue Name:")
        self.issueNameValue = JTextArea(text = str(issueNamePlaceholder), 
                         editable = True,
                         wrapStyleWord = True,
                         lineWrap = True,
                         alignmentX = Component.LEFT_ALIGNMENT,
                         size = (1, 20)
                         )

        # Issue Detail
        self.issueDetailLabel = JLabel(" Issue Detail:")

        #self.issueDetailValue = JTextField(str(issueDetailPlaceholder), 15)
        self.issueDetailValue = JTextArea(text = str(issueDetailPlaceholder), 
                         editable = True,
                         wrapStyleWord = True,
                         lineWrap = True,
                         alignmentX = Component.LEFT_ALIGNMENT,
                         size = (100, 20)
                         )

        # IssueBackground
        self.issueBackgroundLabel = JLabel(" Issue Background:")
        self.issueBackgroundValue = JTextArea(text = str(issueBackgroundPlaceholder), 
                         editable = True,
                         wrapStyleWord = True,
                         lineWrap = True,
                         alignmentX = Component.LEFT_ALIGNMENT,
                         size = (100, 20)
                         )

        # Remediation Detail
        self.issueRemediationLabel = JLabel(" Remediation Detail:")
        self.issueRemediationValue = JTextArea(text = str(remediationDetailPlaceholder), 
                         editable = True,
                         wrapStyleWord = True,
                         lineWrap = True,
                         alignmentX = Component.LEFT_ALIGNMENT,
                         size = (100, 20)
                         )
 
         # Remediation Background
        self.issueRemBackgroundLabel = JLabel(" Remediation Background:")
        self.issueRemBackgroundValue = JTextArea(text = str(remediationBackgroundPlaceholder), 
                         editable = True,
                         wrapStyleWord = True,
                         lineWrap = True,
                         alignmentX = Component.LEFT_ALIGNMENT,
                         size = (100, 20)
                         )  

        # Issue URL
        self.issueURLLabel = JLabel(" URL (path = http://domain/path):")
        self.issueURLValue = JTextArea(text = str(issueURLPlaceholder), 
                         editable = True,
                         wrapStyleWord = True,
                         lineWrap = True,
                         alignmentX = Component.LEFT_ALIGNMENT,
                         size = (1, 20)
                         )                       

        # Issue Port
        self.issuePortLabel = JLabel(" Port:")
        self.issuePortValue = JTextArea(text = str(issuePortPlaceholder), 
                         editable = True,
                         wrapStyleWord = True,
                         lineWrap = True,
                         alignmentX = Component.LEFT_ALIGNMENT,
                         size = (1, 20)
                         )

        # Confidence
        self.confidenceValuesList = ("Certain","Firm","Tentative")
        self.issueConfienceLabel = JLabel(" Confidence [Certain, Firm or Tentative]")
        self.issueConfidenceValue = JComboBox(self.confidenceValuesList)

        # Severity
        self.severityValuesList = ("High","Medium","Low","Information")
        self.issueSeverityLabel = JLabel(" Severity [High, Medium Low or Informational]")
        self.issueSeverityValue = JComboBox(self.severityValuesList)

        # Add Finding button

        self.addFindingButton = JButton("Generate Finding", actionPerformed=self.createScanIssue, alignmentX=Component.CENTER_ALIGNMENT) 


        # -- Group items for display -- #         

        # Group items 
        self.grpIssueSummary = JPanel(GridLayout(0,1))
        self.grpIssueSummary.add(self.issueNameLabel)
        self.grpIssueSummary.add(self.issueNameValue)
        self.grpIssueSummary.add(self.issueDetailLabel)
        self.grpIssueSummary.add(self.issueDetailValue)
        self.grpIssueSummary.add(self.issueBackgroundLabel)
        self.grpIssueSummary.add(self.issueBackgroundValue)
        self.grpIssueSummary.add(self.issueRemediationLabel)
        self.grpIssueSummary.add(self.issueRemediationValue)
        self.grpIssueSummary.add(self.issueRemBackgroundLabel)
        self.grpIssueSummary.add(self.issueRemBackgroundValue)
        self.grpIssueSummary.add(self.issueURLLabel)
        self.grpIssueSummary.add(self.issueURLValue)
        self.grpIssueSummary.add(self.issuePortLabel)
        self.grpIssueSummary.add(self.issuePortValue)
        self.grpIssueSummary.add(self.issueURLLabel)
        self.grpIssueSummary.add(self.issueURLValue)
        self.grpIssueSummary.add(self.issuePortLabel)
        self.grpIssueSummary.add(self.issuePortValue)

        self.grpRatingBoxes = JPanel()
        self.grpRatingBoxes.add(self.issueSeverityLabel)
        self.grpRatingBoxes.add(self.issueSeverityValue)
        self.grpRatingBoxes.add(self.issueConfienceLabel)
        self.grpRatingBoxes.add(self.issueConfidenceValue)
        self.grpRatingBoxes.add(self.addFindingButton)


        # add grps to details frame
        self._detailsPanel = JPanel(GridLayout(0,1))
        self._detailsPanel.add(self.grpIssueSummary)
        self._detailsPanel.add(self.grpRatingBoxes)


        self._findingDetailsPane = JScrollPane(self._detailsPanel)
        # create the main frame to hold details
        self._detailsViewer = self._findingDetailsPane # creates a form for details
        #tabs.addTab("Finding Details", self._detailsViewer)

        self._mainFrame = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._detailsViewer, tabs)
        self._mainFrame.setOneTouchExpandable(True);
        self._mainFrame.setDividerLocation(0.5)
        self._mainFrame.setResizeWeight(0.50)

        print "[+] Finding details panel created"
        print "[+] Rendering..."

        # customize our UI components
        callbacks.customizeUiComponent(self._mainFrame)
        callbacks.customizeUiComponent(self._tabbedPane)
        callbacks.customizeUiComponent(self._detailsPanel)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        print "[+] Done"
        print "[!] Added suite tab initialize complete!"

        return



    def getTabCaption(self):
        return "Generate Finding" 



    def getUiComponent(self):
        return self._mainFrame



    # initiaizes when button is clicked in 'Generate Finding Tab'
    def createScanIssue(self, event):

        print "[!] Finding Detail: "

        print "\t[+] Name:\n\t\t", self.issueNameValue.getText().strip()
        name = self.issueNameValue.getText()
        print "\t[+] Description:\n\t\t", self.issueDetailValue.getText().strip()
        description = self.issueDetailValue.getText()
        print "\t[+] Background:\n\t\t", self.issueBackgroundValue.getText().strip()
        background = self.issueBackgroundValue.getText()
        print "\t[+] Remediation:\n\t\t", self.issueRemediationValue.getText().strip()
        remediation = self.issueRemediationValue.getText()
        print "\t[+] Remediation Background:\n\t\t", self.issueRemBackgroundValue.getText().strip()
        remBackground = self.issueRemBackgroundValue.getText()
        print "\t[+] URL Detail:\n\t\t", self.issueURLValue.getText()
        urlDetail = self.issueURLValue.getText()
        print "\t[+] Port Number:\n\t\t", self.issuePortValue.getText()
        portNumber = self.issuePortValue.getText()
        print "\t[+] Confidence Rating:\n\t\t", self.issueConfidenceValue.getSelectedItem()
        confidenceRating = self.issueConfidenceValue.getSelectedItem()
        print "\t[+] Severity Rating:\n\t\t", self.issueSeverityValue.getSelectedItem()
        severityRating = self.issueSeverityValue.getSelectedItem()
        #print "\t[+] Payload Markers:\n\t\t", self.getSelectionBounds()

        # get highlighted data from request/response tabs in 'Generate Finding'
        #print "[!] Request Selected data:", self._requestViewer.getSelectedData()
        #highRequest = self._requestViewer.getSelectedData()
        #print "converted:", self._helpers.bytesToString(highRequest) 
        #print "[!] Response Selected data:", self._responseViewer.getSelectedData()
        #highResponse = self._responseViewer.getSelectedData()
        #print "converted:", self._helpers.bytesToString(highResponse) 

        # current message is used - should work as long as menu item 'Generate Finding' is not reset or used before finding has been generated.
        requestResponse = self.current_message

        print "\t[+] RequestResponse:\n\t\t", requestResponse
        print "\t[+] Service:\n\t\t", requestResponse.getHttpService()        


        # Collect request and Response Markers...
        #print "[**] Request Bounds: ", self._requestHighlight.getSelectionBounds() 
        requestBounds = self._requestHighlight.getSelectionBounds()
        #print "[**] Response Bounds: ", self._responseHighlight.getSelectionBounds() 
        responseBounds = self._responseHighlight.getSelectionBounds()

        # applyMarkers to request/response
        # callbacks.applyMarkers(requestResponse, None, [array('i', (data[1], data[2]))])
        self.reqMarkers = [requestBounds[0],requestBounds[1]]
        print "\t[+] Request Reporting Markers:\n\t\t", self.reqMarkers
        self.resMarkers = [responseBounds[0],responseBounds[1]]
        print "\t[+] Response Reporting Markers:\n\t\t", self.resMarkers

        print "*" * 60
        print "[!] Attempting to create custom scan issue."
        # Call AddScanItem class to create scan issue!!
        finding_array = [urlDetail, name, 134217728, severityRating, confidenceRating, background, remBackground, description, remediation, requestResponse]

        issue = ScanIssue(self, finding_array, self.current_message, self.reqMarkers, self.resMarkers, self._helpers, self._callbacks)
        self._callbacks.addScanIssue(issue)

        # Done
        print "[+] Finding Generated!"


    def getRequestResponseText(self):

        messages = self.ctxMenuInvocation.getSelectedMessages()

        # parses currently selected finding to a string
        if len(messages) == 1 :

            for self.m in messages:

                requestResponse = self.m
                # add requestResponseWithMarkers to be global so can be included in scanIssue
                self.current_message = requestResponse

                # get request data and convert to string
                requestDetail = requestResponse.getRequest()  
                try: 
                    requestData = self._helpers.bytesToString(requestDetail) # converts & Prints out the entire request as string     
                except:
                    requestData = '[-] No Request Detail in this RequestResponse'
                    pass
                # get response data and convert to string
                responseDetail = requestResponse.getResponse()
                try:
                    responseData = self._helpers.bytesToString(responseDetail) # converts & Prints out the entire request as string 
                except:
                    responseData = '[-] No Response Detail in this RequestResponse' 
                    pass 
                requestData = self._helpers.bytesToString(requestDetail) # converts & Prints out the entire request as string     


            # send request string to 'Supporting Request' tab - 'True' because it is a request!
            self._requestViewer.setMessage(requestData, True)
            # for higlighting markers..
            self._requestHighlight.setText(requestData)

            # send response string to 'Supporting Response' tab
            self._responseViewer.setMessage(responseData, False) # set False as is a response not request... 
            # for higlighting markers..
            self._responseHighlight.setText(responseData)
           


    def getFindingDetails(self):

            messages = self.ctxMenuInvocation.getSelectedMessages()

            print "*" * 60
            print "[+] Handling selected request: ", self.current_message

            if len(messages) == 1:
                for m in messages:           

                    # URL
                    #print "[!] Selected Request's URL: \n", self._helpers.analyzeRequest(m).getUrl()
                    self.issueURLValue.setText(str(self._helpers.analyzeRequest(m).getUrl())) # update finding info

                    # Protocol
                    #print "[!] Request's Protocol: \n", m.getProtocol()

                    # Request Port
                    #print "[!] Request's Port: \n", m.getPort()
                    self.issuePortValue.setText(str(m.getPort())) # update finding info
                    print "*" * 60


# API hook...

    def getHttpMessages(self):

        return [self.m]


# Actions on menu click...

    def actionPerformed(self, actionEvent):
        print "*" * 60
        print "[+] Request sent to 'Generate Finding'"
        try:
            # When clicked!! 
            self.getRequestResponseText()
            self.getFindingDetails()
        except:
            tb = traceback.format_exc()
            print tb


# create Menu

    def createMenuItems(self, ctxMenuInvocation):
        self.ctxMenuInvocation = ctxMenuInvocation
        return [self.menuItem]
    

   
# 
# class implementing IScanIssue
#

class ScanIssue(IScanIssue):

    def __init__(self, extender, finding_array, requestResponse, requestMarkers, responseMarkers, helpers, callbacks):

        # finding_array contents example
        # finding_array = [urlDetail, name, 134217728, severityRating, confidenceRating, background, None, description, remediation]

        # sets apply markers, if they are selected during finding generation...
        self.requestMarkers = requestMarkers
        self.responseMarkers = responseMarkers
        self.requestResponse = callbacks.applyMarkers(requestResponse, [array('i',(requestMarkers[0],requestMarkers[1]))], [array('i',(responseMarkers[0],responseMarkers[1]))])
        # [current_message, modified_message] would propose a "compare responses" button when viewing the results
        analyzedRequest = helpers.analyzeRequest(requestResponse)

        # basic information
        self._findingUrl = analyzedRequest.getUrl()
        self._severity = finding_array[3]
        self._confidence = finding_array[4]
        self._issueName = finding_array[1]
        self._issueType = finding_array[2] #6296666 # trial arbitrary chosen # extension generated = 134217728 or finding[2]

        # issueDetail
        self._issueDetail = finding_array[7] 

        # issueBackground
        self._issueBackground = finding_array[5]

        # issueRemediation
        self._remediationDetail = finding_array[8]

        # remediationBackground
        self._remBackground = finding_array[6]

    #
    # implement IScanIssue
    #

    def getUrl(self):
        return self._findingUrl

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return self._issueType

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence 

    def getIssueBackground(self):
        return self._issueBackground

    def getRemediationBackground(self):
        return self._remBackground

    def getIssueDetail(self):
        return self._issueDetail 

    def getRemediationDetail(self):
        return self._remediationDetail 

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.requestResponse.getHttpService()


            













