# Generate-Finding
BurpSuite extension to generate and edit manual findings


# What does it do?
 - The extension provides the user the ability to create a arbitrary finding from any request/response that is in Burp.


# Requirements
Ensure you have a standalone version of jython >= 2.7 installed.

Add this extension via the in-built Burpsuite Extender options:
 - Extender -> Extensions -> Add


# Usages:

How?

Fun part... The extension works in nearly every burp tool by right clicking on the request/response and selecting 'Generate Finding' from the menu.

Step 1: Load Extension

  - Pretty Straight forward, you will need a standalone Jython jar file.
  - Then use the Burp extender interface and load the 'generateFinding.py' extension.

Step 2: Finding Indentification

  - Test away until you want to create a new arbitrary finding.
  - Then right click on the request/response and select 'Generate Finding'

Step 3: Finding Detail

  - Some of the finding detail is parsed from picking up the request, the rest can be added by navigating to the 'Generate Finding' tab - where you will see the request/response you sent to it.
  - Use the dropdown boxes to assign the risk and confidence (normally 'Firm' as a manual finding!).
  - Use the tabs in the lower pane to view details. Highlight the relevant areas that need to be identified in the report as noticeable supporting evidence or data:
  - Click 'Generate Finding' - This will send your newly created finding to the Target Section under the relevant host

Step 4: Review finding in Burp's Target Tool [Optional]

  - If youre not happy with the highlighted markers or data, Delete the finding from the target and use the 'Generate Finding' tab to modify and re-create it!

Step 4: Reporting

  - Use Burps reporting tool to create the assessment report with data 
      - (select all requests to be included then right click, if more than one issue or right click on host and select 'issues' -> 'report issues for this host').
  - The wizard will allow you to deselect issues that the scanner creates...

Step 5: View Report

  - Supporting data and finding information output to burp Report


Hope you enjoy using it.

[more work to come...]
