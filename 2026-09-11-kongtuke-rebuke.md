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
