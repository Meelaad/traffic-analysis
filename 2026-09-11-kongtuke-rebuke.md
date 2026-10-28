# 2026-09-11 Kongtuke Rebuke

Exercise: https://www.malware-traffic-analysis.net/2026/09/11/index.html

## Background
A Windows host on the overhands[.]org network (LAN 10.9.11[.]0/24, domain controller 10.9.11[.]2, WIN-GTWXC9UYSE4) got infected through a Kongtuke fake verification page. This is the ClickFix trick, where the page tells the user to paste a command into the Run window. There were no alerts this time, only the pcap.

The job was to find the infected host's IP, MAC address and host name, the user account, and the user's full name.

## Answers
- Infected host IP: 10.9.11[.]135
- MAC address: 08:d4:0c:7a:29:1e
- Host name: DESKTOP-6T17ZFM
- User account: gmcdowell
- Full name: Gabriel McDowell

How I found them:
- 10.9.11[.]135 is the only client in the pcap. The only other LAN address that sends anything is the domain controller.
- The MAC is the source MAC on every packet from 10.9.11[.]135.
- There's no DHCP in this pcap, so the host name couldn't come from there like last time. The NetBIOS browser announcements from 10.9.11[.]135 have DESKTOP-6T17ZFM, and the Kerberos traffic has a ticket for host/desktop-6t17zfm.overhands[.]org.
- The user is in the Kerberos CNameString field (gmcdowell).
- LDAP to the domain controller was encrypted, so the full name wasn't there. It was in the SAMR traffic instead. The host asked the domain controller about gmcdowell over SAMR, and the QueryUserInfo reply has the full name.

## Timeline (UTC, 2026-09-11)
- 20:05:55 Capture starts. The browser loads quadcinema[.]com (104.196.13[.]170), along with jQuery and Google Analytics.
- 20:05:56 One second later the browser connects to aatthews[.]cfd over QUIC. This is most likely the Kongtuke script injected into the site, which shows the fake verification page.
- 20:06:33 37 seconds later, something that isn't the browser connects to winrun2915[.]com. The TLS fingerprints show the difference. The browser's JA4 starts with t13d1516h2_8daaf6152771 and this one with t13d2013h1_2b729b4bf6f3, which is a Windows program. This is most likely the command the user pasted.
- 20:06:36 The same kind of client connects to logincrypt8338[.]com, and at 20:06:38 to opscast3707[.]net. The first opscast3707[.]net connection downloads 7.2 MB.
- 20:06:42 to 20:06:46 Small downloads from www.xos-aploq[.]com and jaw.xos-aploq[.]com.
- 20:06:47 35 MB from nodejs.org, about the size of the Node.js zip for Windows. Same kind of client again.
- 20:06:52 86 kB from soft.xos-aploq[.]com.
- 20:06:57 Five seconds later, HTTP C2 starts to know.mom-nower[.]com (86.106.87[.]134) on port 80. It polls about every 10 seconds. The URLs are random, but they all contain the same 64 character hex ID. The user agent says Firefox 137, but the browser's own traffic looks like Edge. The first POST at 20:07:16 is 12.9 kB, probably details about the host.
- 20:07:41 From here the three numbered domains get a new HTTPS connection in turn, one every 16 seconds, so each domain every 48 seconds. Each one is only a few kB. This is a second C2 channel, separate from the HTTP one.
- 20:08:06 The C2 sends back something with content, and 0.1 seconds later the host asks the domain controller over SAMR for the members of the Domain Computers group. That's what net group "domain computers" /domain does.
- 20:08:59 Packages get downloaded from registry.npmjs.org (15 connections, 830 kB). This fingerprint (t13d521100_b262b3658495) is different from both of the others, which fits Node.js itself.
- 20:10:03 The HTTP C2 comes back after a one minute gap with a new ID, so the malware probably restarted after installing the packages.
- 20:15:33 Another C2 reply, and 0.05 seconds later the host looks up gmcdowell's account and groups over SAMR, like net user gmcdowell /domain.
- 20:19:10 Both C2 channels stop and the host goes almost quiet.
- 20:22:07 gmcdowell gets a new Kerberos ticket (AS-REQ) and there's a burst of Microsoft and Office sign-in traffic. There's no ticket request for the computer account, so this looks like the user signing out and back in, not a reboot.
- 20:22:17 Ten seconds later the HTTP C2 is back with the same ID as before 20:19, so it's set to start when the user logs in. Now it goes through 9 hostnames on 4 domains, sending a 75 byte POST and a POST of about 26 kB to each one. Every request gets a 400 or 406 error back, including the ones to know.mom-nower[.]com. The HTTPS channel to the three numbered domains doesn't come back.
- 20:27:05 Capture ends.

## Indicators
Domains and IPs:
- quadcinema[.]com, 104.196.13[.]170 (the site the user visited, probably compromised)
- aatthews[.]cfd, 172.67.205[.]86 and 104.21.22[.]148 (probably the Kongtuke script)
- winrun2915[.]com, logincrypt8338[.]com, opscast3707[.]net (HTTPS C2)
- www.xos-aploq[.]com, jaw.xos-aploq[.]com, soft.xos-aploq[.]com (downloads)
- know.mom-nower[.]com, 86.106.87[.]134 (HTTP C2)
- now.comonto-rsr[.]com, firt.comonto-rsr[.]com, start.comonto-rsr[.]com (HTTP C2 after the sign-in)
- stream.fif-lost[.]com, hyko.fif-lost[.]com (same)
- second.bert-hits[.]com, gets.bert-hits[.]com, www.bert-hits[.]com (same)
- 62.3.53[.]87 and 146.70.139[.]165 (C2 IPs that aren't Cloudflare, see below)

HTTP C2:
- Every URL has an ampersand and a 64 character hex ID in it. This host used 4a0fd955c05d43841a9a8d921ceec63b0dc5b431a9fb54b33ad7848707bc16e9 until 20:08:57 and 99099296646b5ffb8188092fb5030b7890c1de2d6a058cab178d4548c4dca1ab after that.
- User agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0
- The bodies start with 1f8b, so they're gzip, but what's inside is encrypted.

Other things worth knowing:
- Most of the IPs here are Cloudflare (104.21.x.x and 172.67.x.x), which lots of normal sites share. Blocking the domains works better than blocking those IPs. The only C2 IPs that aren't Cloudflare are 86.106.87[.]134, 62.3.53[.]87 and 146.70.139[.]165.
- Since almost everything was HTTPS, JA4 was the easiest way to tell the programs apart. There were three: the browser, a Windows program (the pasted command and the HTTPS C2) and Node.js.
- A Firefox user agent from a host whose browser is Edge is a good thing to alert on, like curl was in the Natureforce exercise.
- Two of the C2 replies were followed by SAMR queries to the domain controller within a tenth of a second. That timing is how I could tie the domain lookups to the C2, even without being able to read the commands.
- Downloading Node.js isn't bad by itself, but a normal user's PC getting Node.js and npm packages a minute after visiting a website is worth a look.

## MITRE ATT&CK
- T1189 Drive-by Compromise (likely): the browser loads aatthews[.]cfd one second after the site.
- T1204.004 User Execution: Malicious Copy and Paste (likely): a program that isn't the browser starts connecting out 37 seconds later, which fits the user pasting the command from the fake verification page.
- T1105 Ingress Tool Transfer (seen): Node.js, the xos-aploq[.]com files, 7.2 MB from opscast3707[.]net and the npm packages.
- T1059.007 Command and Scripting Interpreter: JavaScript (likely): Node.js gets downloaded and the HTTP C2 starts 5 seconds after the last file.
- T1071.001 Application Layer Protocol: Web Protocols (seen): HTTP C2 to know.mom-nower[.]com and HTTPS C2 to the three numbered domains.
- T1573 Encrypted Channel (seen): the HTTP C2 bodies are gzip and then encrypted.
- T1069.002 Permission Groups Discovery: Domain Groups (seen): the Domain Computers members get looked up right after a C2 reply.
- T1087.002 Account Discovery: Domain Account (seen): gmcdowell's account and groups get looked up right after a C2 reply.
- T1547 Boot or Logon Autostart Execution (likely): the HTTP C2 comes back with the same ID 10 seconds after the user signs in again.
- T1008 Fallback Channels (seen): after the sign-in it goes through 9 C2 hostnames on 4 domains.

"Seen" means it's in the traffic. "Likely" means the traffic fits it, but the content was encrypted so I can't prove it.

## What I would do next
- Isolate DESKTOP-6T17ZFM from the network.
- Block the domains above at the proxy and DNS, and the three non-Cloudflare IPs at the firewall.
- Reset the password for gmcdowell.
- The malware listed the domain's computers, so check the domain controller and the other hosts for logons from 10.9.11[.]135 or by gmcdowell after 20:06. In this pcap the host only talked to the domain controller.
- Find what starts Node.js when gmcdowell logs in (Run keys, the Startup folder, scheduled tasks) and remove it, or just reimage the host.
- Search the proxy logs for the Firefox 137 user agent from hosts that don't have Firefox, for URLs with a 64 character hex ID, and for Node.js downloads to PCs that aren't used for development.
- Remind users that a real CAPTCHA never asks you to paste anything into the Run window.

## What I couldn't see
- The command the user pasted and the files from xos-aploq[.]com and opscast3707[.]net, because they were HTTPS.
- The C2 commands. The bodies are encrypted, so I only know what two of them did from the SAMR traffic right after.
- What the 26 kB uploads at the end were, and why every server rejected them.
- Whether the HTTPS C2 and the Node.js C2 are the same malware or two different ones, and why the HTTPS one never came back after 20:19. The exercise page has the malware files for reverse engineers, but I stuck to the pcap.
