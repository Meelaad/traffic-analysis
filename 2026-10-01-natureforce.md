# 2026-10-01 Natureforce

Exercise: https://www.malware-traffic-analysis.net/2026/10/01/index.html

## Background
The SOC got two alerts for a Windows host on the natureforce[.]com network (LAN 10.10.1[.]0/24, domain controller 10.10.1[.]10):
- a Windows EXE sent from 107.175.82[.]242 over port 9000
- CNCmachineRMS RAT C2 traffic to 195.64.128[.]106:443

The job was to check the pcap, confirm the alerts and find the infected host and user.

## Answers
- Infected host IP: 10.10.1[.]128
- MAC address: 00:22:fb:ec:7e:e7
- Host name: DESKTOP-4VGYQX7
- User account: bdiaz
- SHA-256 of the EXE from 107.175.82[.]242:9000: b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061

How I found them:
- The IP is the only internal host talking to 107.175.82[.]242 (tshark -z conv,ip).
- The MAC is the source MAC on every packet from 10.10.1[.]128, and the DHCP request shows the same MAC with the host name DESKTOP-4VGYQX7. NetBIOS name registrations show the same name.
- The user comes from the Kerberos traffic to the domain controller. The CNameString field shows bdiaz next to the computer account DESKTOP-4VGYQX7$.
- For the hash I exported the HTTP objects with tshark --export-objects, ran sha256sum on runner_ilove.exe and deleted the file right after. It starts with MZ, so it's a Windows executable, and it's 1,646,592 bytes.

## Timeline (UTC, 2026-10-01)
- 19:27:27 Capture starts. Normal Windows traffic (connectivity check, Edge, Microsoft telemetry).
- 19:28:30 DNS and HTTPS to www.ars-soar[.]com (54.201.5[.]185).
- 19:28:31 One second later, HTTPS to sorrelapse[.]best (44.203.10[.]190). The timing looks like the first site sending the browser to the second one, which is how a compromised site usually hands off to a malicious script.
- 19:29:00 GET http://holtandberyl[.]com/prw and then /crv (35.170.55[.]9) with the user agent curl/8.21.0. Both get a 301 to HTTPS, so the content is encrypted. A normal user doesn't run curl, so this is most likely a command the user was tricked into pasting (the fake CAPTCHA "ClickFix" trick).
- 19:30:36 GET http://107.175.82[.]242:9000/wilow/runner_ilove.exe, again with curl/8.21.0. This is the EXE from the first alert.
- 19:30:44 The host starts talking to 195.63.128[.]106 on port 443. This goes on until the end of the capture.
- 19:31:04 Windows downloads the Sectigo code signing root certificate, so the EXE is probably signed and Windows was checking the signature.
- 20:07:58 Capture ends. The C2 connection is still active.

## Indicators
Domains and IPs:
- www.ars-soar[.]com, 54.201.5[.]185 (first suspicious site)
- sorrelapse[.]best, 44.203.10[.]190 (redirect right after it)
- holtandberyl[.]com, 35.170.55[.]9 (where curl went first)
- hxxp://107.175.82[.]242:9000/wilow/runner_ilove.exe (EXE download)
- 195.63.128[.]106:443 (C2)

File:
- runner_ilove.exe, 1,646,592 bytes
- SHA-256 b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061

Other things worth knowing:
- The user agent curl/8.21.0 coming from a Windows desktop is a good thing to alert on by itself.
- The C2 is on port 443 but it isn't real TLS. There is no client hello with a server name and no certificate. Wireshark only guesses "SSL" for some packets. Something that uses 443 without TLS stands out if you look at it.
- The alert says the C2 is 195.64.128[.]106, but there are no packets to that IP in the pcap. The traffic goes to 195.63.128[.]106, so I think the alert has a typo.

## MITRE ATT&CK
- T1189 Drive-by Compromise (likely): the browser visits ars-soar[.]com and gets passed to sorrelapse[.]best right away.
- T1204.004 User Execution: Malicious Copy and Paste (likely): curl runs on the desktop right after the web visit, which fits a fake CAPTCHA page telling the user to paste a command.
- T1105 Ingress Tool Transfer (seen): curl downloads runner_ilove.exe from 107.175.82[.]242.
- T1571 Non-Standard Port (seen): the EXE comes over port 9000, and the C2 uses 443 without TLS.
- T1219 Remote Access Tools (seen in the alert and the traffic): a long RMS-based RAT session to 195.63.128[.]106.

"Seen" means it's in the traffic. "Likely" means the traffic fits it, but the content was encrypted so I can't prove it.

## What I would do next
- Isolate DESKTOP-4VGYQX7 from the network.
- Block the domains and IPs above at the proxy and firewall.
- Reset the password for bdiaz, since a RAT can see anything typed on the host.
- Search the proxy and DNS logs for the other indicators and for curl/8.21.0 from Windows hosts, to see if anyone else got hit.
- Look for runner_ilove.exe or its hash on other machines with the EDR.

## What I couldn't see
- What /prw and /crv returned, because they were HTTPS.
- What the RAT actually did. Its traffic isn't readable, so I can only say it was connected for about 37 minutes.
- Whether the 11 MB download from a Visual Studio blob storage server at 19:30:29 has anything to do with the infection. It happened right before the EXE download but it's a normal Microsoft server, so I left it out of the indicators.
