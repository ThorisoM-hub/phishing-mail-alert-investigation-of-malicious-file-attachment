# Project: Phishing Mail Alert - Investigation of Malicious File Attachment

## Platform:
- **Let'sDefend**  
- **Event ID**: 45

## Tools:
- **VirusTotal**: Used to analyze URLs, files, and hashes.
- **URLHaus**: Utilized to check URL reputation.
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

  ![Malicious URL Analysis](images/url_analysis.png)  
  *Caption: Analysis of the malicious URL in VirusTotal.*

### Payload and Hash Analysis:
- **SHA-256 Hash**: `101bf67953ee39065a917a37670cc43836cf5c0a938082f4038515efebddcc04`
  - **Findings**: The hash matched a known malicious payload, and it was flagged as malicious on VirusTotal.

  ![Payload Hash Analysis](images/payload_hash_analysis.png)  
  *Caption: SHA-256 hash analysis on VirusTotal showing malicious status.*

### Exploit Detection:
- **Exploit**: CVE-2017-11882
  - **Action Taken**: After identifying the CVE in VirusTotal, I visited the official website to gather more information on the exploit.

  ![Exploit CVE-2017-11882](images/exploit_cve_research.png)  
  *Caption: Researching the CVE-2017-11882 exploit on the official website.*

### IP Address and Network Activity:
- **IP Destination**: `5.135.143.133`
  - **Action Taken**: I traced the network connections via endpoint security, examining browser history and process lists to identify the destination IP. Further log management and network logs confirmed this IP address as a destination.

  ![Network Activity](images/network_activity.png)  
  *Caption: Investigating network activity related to the malicious IP.*

---

## Incident Response Steps:

1. **Containment/Isolation**:  
   The first step in addressing the threat was isolating the affected system to prevent further compromise. This was done using **EDR (Endpoint Detection and Response)**, which allowed for the quick containment of the infected device from the network.

   ![Containment Step](images/containment_step.png)  
   *Caption: Isolating the affected system using EDR.*

2. **Investigation and Analysis**:  
   I began by extracting key information from the phishing email, such as the SMTP address, source, and destination details. I then used VirusTotal and URLHaus to analyze the attachments, URLs, and hashes.

   ![Investigation Analysis](images/investigation_analysis.png)  
   *Caption: Performing investigation and analysis on the phishing email.*

3. **Review Indicators of Compromise (IOCs)**:  
   - Checked the reputation of the sender’s email address and the malicious URL through VirusTotal.
   - Cross-referenced hashes and identified known malicious activity.

   ![IOC Review](images/ioc_review.png)  
   *Caption: Reviewing indicators of compromise (IOCs).*

4. **Examine Network Activity**:  
   I reviewed endpoint security logs, browser history, and network connections. The destination IP `5.135.143.133` was identified, confirming the activity was associated with a malicious payload.

   ![Network Activity](images/network_activity_step.png)  
   *Caption: Investigating network activity related to the malicious IP.*

5. **File and Payload Analysis**:  
   - The Excel file attachment was identified using its MD5 hash and verified against VirusTotal results.
   - SHA-256 hash matching led to identifying the malicious nature of the file.

   ![File and Payload](images/file_payload_analysis.png)  
   *Caption: File and payload analysis on VirusTotal.*

6. **Mitigation/Response**:  
   - After identifying the malicious activity, the infected system was isolated using EDR to prevent the spread of the malware. Further steps were taken to secure the environment by patching the CVE and blocking the malicious IP.

   ![Mitigation Response](images/mitigation_response.png)  
   *Caption: Mitigation actions, including blocking malicious IPs and patching the CVE.*

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
   The affected device was isolated using **EDR (Endpoint Detection and Response)** to prevent the spread of the malware. Necessary patches were applied to fix the identified exploit. The malicious IP was blocked, and additional monitoring was put in place to prevent future attacks of this nature.








  
