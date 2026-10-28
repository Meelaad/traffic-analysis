# traffic-analysis

My write-ups of packet capture exercises from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/). Each one has what happened, a timeline, the indicators and a MITRE ATT&CK mapping.

I don't upload the pcaps or anything extracted from them. Each write-up links to the exercise page instead. I didn't run anything from the captures. The analysis was done with tshark (Wireshark's command line version).

## Write-ups
- [2026-10-01 Natureforce](2026-10-01-natureforce.md): Windows host downloads an EXE over port 9000, then RAT C2 traffic
- [2026-09-11 Kongtuke Rebuke](2026-09-11-kongtuke-rebuke.md): fake verification page (ClickFix), Node.js malware with HTTP C2, then domain discovery over SAMR
