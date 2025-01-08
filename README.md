#  Phishing Mail Alert - Investigation of Malicious File Attachment

## Platform:
- **LetsDefend**  
- **Event ID**: 45

## Tools:
- **VirusTotal**: Used to analyze URLs, files, and hashes.
- **URLHaus**: Utilized to check URL reputation.
- **AnyRun**: For deeper file analysis (if applicable).
- **EDR (Endpoint Detection and Response)**: Used to isolate the affected system.

## Role:
- **Security Analyst** (Investigation Level)

## SMTP Details:
- **SMTP Address**: 49.234.43.39
- **Source Address**: `accounting@cmail.carleton.ca`
- **Destination Address**: `richard@letsdefend.io`
- **Email Subject**: Invoice
- **Device Action**: Allowed

## Artifacts Collected:

### URL Analysis:
- **Malicious URL**: [http://andeluctabeach.net/Anage/network-exe](http://andeluctabeach.net/Anage/network-exe)
  - **Action Taken**: After uploading the malicious attachment to VirusTotal, I navigated to the URL relations and discovered this website associated with the threat.

   ### Malicious URL Analysis
<p align="center">
  <img src="https://imgur.com/wWEEuHr.png" alt="malicious URL Analysis" width="100%" />
</p>
  *Caption: Analysis of the malicious URL in VirusTotal.*

###  Evidence from URLhaus:

The malicious hash was also found on URLhaus, a platform that tracks malicious URLs and payloads. Below is an image of the URLhaus entry confirming the malicious nature of the payload:

The hash was initially identified using the website [http://andeluctabeach.net/Anage/network-exe](http://andeluctabeach.net/Anage/network-exe). This platform facilitated the discovery and extraction of the malicious hash from a suspicious payload.

<p align="center">
  <img src="https://imgur.com/ySIgLGm.png" alt="URLhaus Hash Analysis" width="100%" />
</p>

### Payload and Hash Analysis:
- **SHA-256 Hash**: `101bf67953ee39065a917a37670cc43836cf5c0a938082f4038515efebddcc04`
  - **Findings**: The hash matched a known malicious payload, and it was flagged as malicious on VirusTotal.

<p align="center">
  <img src="https://imgur.com/1cejDo6.png" alt="Payload and Hash analysis" width="100%" />
</p>
   
  *Caption: SHA-256 hash analysis on VirusTotal showing malicious status.*

*Caption: SHA-256 hash entry on URLhaus indicating malicious activity.*
### Exploit Detection:
- **Exploit**: CVE-2017-11882
  - **Action Taken**: After identifying the CVE in VirusTotal, I visited the official website to gather more information on the exploit.

 ### Exploit CVE-2017-1188
<p align="center">
  <img src="https://imgur.com/F3OVZQZ.png" alt="Exploit CVE-2017-1188" width="100%" />
</p>
  *Caption: Researching the CVE-2017-11882 exploit on the official website.*

### IP Address and Network Activity:
- **IP Destination**: `5.135.143.133`
  - **Action Taken**: I traced the network connections via endpoint security, examining browser history and process lists to identify the destination IP. Further log management and network logs confirmed this IP address as a destination.

<p align="center">
  <img src="https://imgur.com/rnJp1a1.png" alt="Network Activity" width="75%" />
  <img src="https://imgur.com/ZkTx8JW.png" alt="Network Activity" width="75%" />
</p>
---
### Log management
<p align="center">
  <img src="https://imgur.com/TYXNZ2e.png" alt="Log Management" width="100%" />
  <img src="https://imgur.com/bP2ecrP.png" alt="Log Management" width="100%" />
</p>

  
  *Caption: Investigating network activity and log management related to the malicious IP.*

---

## Incident Response Steps:

1. **Alert Detection**:  
   The first step of the investigation was identifying the alert within the Let'sDefend platform. Below is a picture showing the detected phishing alert.

   
    ### Alert Detection
<p align="center">
  <img src="https://imgur.com/Gwbg1Pz.png" alt="Alert Detection" width="100%" />
</p>

   *Caption: Detection of the phishing email alert within the Let'sDefend platform.*

2 **Containment/Isolation**:  

   The first step in addressing the threat was isolating the affected system to prevent further compromise. This was done using **EDR (Endpoint Detection and Response)**, which allowed for the quick containment of the infected device from the network.
    
    ### Containment Step
  <p align="center">
  <img src="https://imgur.com/eP3q7lX.png" alt="Containment Step" width="100%" />
</p>
   *Caption: Isolating the affected system using EDR.*

3. **Investigation and Analysis**:  
   I began by extracting key information from the phishing email, such as the SMTP address, source, and destination details. I then used VirusTotal and URLHaus to analyze the attachments, URLs, and hashes.
   
    ### Investigation Analysis
<p align="center">
  <img src="https://imgur.com/4tIEB7k.png" alt="Alert Detection" width="100%" />
</p>
   *Caption: Performing investigation and analysis on the phishing email.*

5. **Review Indicators of Compromise (IOCs)**:  
   - Checked the reputation of the sender’s email address and the malicious URL through VirusTotal.
   - Cross-referenced hashes and identified known malicious activity.

 ### IOC Review
<p align="center">
  <img src=".png" alt="Alert Detection" width="100%" />
</p>
   *Caption: Reviewing indicators of compromise (IOCs).*

7. **Examine Network Activity**:  
   I reviewed endpoint security logs, browser history, and network connections. The destination IP `5.135.143.133` was identified, confirming the activity was associated with a malicious payload.

   ![Network Activity](images/network_activity_step.png)  
   *Caption: Investigating network activity related to the malicious IP.*

8. **File and Payload Analysis**:  
   - The Excel file attachment was identified using its MD5 hash and verified against VirusTotal results.
   - SHA-256 hash matching led to identifying the malicious nature of the file.

   ![File and Payload](images/file_payload_analysis.png)  
   *Caption: File and payload analysis on VirusTotal.*

9. **Mitigation/Response**:  
   - After identifying the malicious activity, the infected system was **isolated** using EDR to prevent the spread of the malware. Further steps were taken to secure the environment by patching the CVE and preparing for continued monitoring.

   ![Mitigation Response](images/mitigation_response.png)  
   *Caption: Mitigation actions, including isolating the infected system and preparing for further investigation.*

---

## Playbook Results:

- After executing the playbook to mitigate the phishing threat, I followed predefined steps for analyzing the email, identifying the malicious file, and isolating the affected system. Below is the result summary of the playbook execution.

  ![Playbook Results](images/playbook_results.png)  
  *Caption: Results from executing the playbook, showing key investigation and response steps.*

---

## YouTube Demonstration

Check out the **YouTube demonstration** for a walkthrough of the investigation process:

[Phishing Mail Alert Investigation - YouTube](https://www.youtube.com/watch?v=your_video_id)

---

## Conclusion:

- **Summary**:  
   The phishing email contained a malicious Excel file that exploited a known vulnerability (CVE-2017-11882). The investigation successfully identified indicators of compromise (IOCs) like malicious URLs, payload hashes, and suspicious network activity.
  
- **Remediation**:  
   The affected device was **isolated** using **EDR (Endpoint Detection and Response)** to prevent the spread of the malware.Additional monitoring and investigation steps were planned to prevent future attacks of this nature.









  
