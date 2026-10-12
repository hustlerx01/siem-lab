"""Synthetic Wazuh-shaped events for scenarios not covered by the public EVTX samples
(4625 spray, 4624-after-failures, 4672 user vs SYSTEM/machine, WMI->shell). Clearly synthetic."""
import json
from pathlib import Path

def ev(eid, ch="Security", **d):
    return {"win": {"system": {"eventID": str(eid), "channel": ch, "computer": "WS01.lab.local",
                               "systemTime": "2026-10-11T10:00:00Z"}, "eventdata": d}}

SYS = "Microsoft-Windows-Sysmon/Operational"
spray = [ev(4625, targetUserName=u, ipAddress="192.168.56.10", logonType="3") for u in ["alice", "bob", "carol", "dave", "erin", "frank"]]
brute = [ev(4625, targetUserName="svc_backup", ipAddress="192.168.56.11", logonType="3") for _ in range(5)] + \
        [ev(4624, targetUserName="svc_backup", ipAddress="192.168.56.11", logonType="3")]
priv = [ev(4672, subjectUserName="ansar.admin", privilegeList="SeDebugPrivilege SeBackupPrivilege"),
        ev(4672, subjectUserName="SYSTEM", privilegeList="SeDebugPrivilege"),
        ev(4672, subjectUserName="WS01$", privilegeList="SeSecurityPrivilege")]
wmi = [ev(1, SYS, parentImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe", image=r"C:\Windows\System32\cmd.exe", commandLine="cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1 2>&1"),
       ev(1, SYS, parentImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe", image=r"C:\Windows\System32\WerFault.exe")]

if __name__ == "__main__":
    out = Path("samples/synthetic"); out.mkdir(parents=True, exist_ok=True)
    for name, evs in [("spray_4625", spray), ("logon_after_failures", brute), ("special_privs_4672", priv), ("wmi_shell", wmi)]:
        (out / f"{name}.jsonl").write_text("".join(json.dumps(e) + "\n" for e in evs))
        print(name, len(evs))
