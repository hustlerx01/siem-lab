# Interview notes — siem-lab

**Q: Walk me through the pipeline.** Suricata sniffs traffic or replays a pcap and writes JSON events to eve.json. Wazuh's logcollector reads that file, decodes it and runs it through rules, including my local_rules.xml. Alerts go to the indexer through Filebeat, and I look at them in the dashboard. Windows events come from an agent (eventchannel) or, in this lab, from EVTX that I convert to JSON.

**Q: IDS vs IPS?** An IDS watches a copy of the traffic and alerts. An IPS sits inline (Suricata NFQUEUE/AF_PACKET inline) and can drop packets. I run IDS mode here. IPS adds a risk that false positives block real traffic.

**Q: How does your password-spray rule work?** It is a frequency rule over 4625 failures. The source IP must be the same (`same_field`) and the target users must differ (`different_field`), with ≥5 in 120s. Brute force is the opposite pattern: one user, many attempts. For Kerberos I use 4771 status 0x18 (bad pre-auth password) and 4768 status 0x6 (unknown user, which points to enumeration).

**Q: Why skip SYSTEM and machine accounts on 4672?** They get special privileges on every logon, so alerting on them only adds noise. A human account getting SeDebugPrivilege is worth a look.

**Q: What LSASS access masks matter?** 0x1010, 0x1410 and 0x1fffff are typical of Mimikatz and procdump reading memory. Normal processes like AV also touch LSASS, so tune with exclusions by SourceImage.

**Q: A bug you found?** Kerberos status arrives as 0x00000006 in real logs. My first regex `^0x6$` would never fire. The test against a real spray sample caught it.

**Q: How do you reduce false positives?** Baseline first. Then whitelist known sources (vuln scanners for the nmap rule), use thresholds and timeframes, and keep severity levels honest. Every rule gets a test with a benign negative case (WerFault under WmiPrvSE, SYSTEM on 4672).

**Q: Why MITRE mapping?** It gives a common language for coverage and makes gaps visible. It also tells the analyst the likely next steps (e.g. T1003.001 credential dumping is usually followed by lateral movement).

**Q: Limits of your lab?** Most logic is validated offline. Live Wazuh results come from my own run (see README). The data is a small set of public attack samples plus synthetic events, not production traffic.

**Q: Alert 100150 fires — your triage?** Check the SourceImage path and signature, the user and host, the parent process, and any network connections around that time. Then look for 4624 type 3/10 logons using that account from other hosts. If it's confirmed, contain the host and reset credentials.
