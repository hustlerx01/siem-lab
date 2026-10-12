import json, re, subprocess, shutil, xml.etree.ElementTree as ET
from pathlib import Path
import pytest
from wazuh_sim import Engine, load, RULES

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {  # detection -> (rule ids, MITRE ids that must be present)
    "password_spray_4625": (["100110"], {"T1110.003"}),
    "kerberos_spray_4771": (["100111"], {"T1110.003"}),
    "kerberos_enum_4768": (["100112"], {"T1110.003"}),
    "logon_after_failures": (["100114"], {"T1110"}),
    "special_privileges_4672": (["100120"], {"T1078"}),
    "security_log_cleared": (["100130"], {"T1070.001"}),
    "suspicious_scriptblock": (["100140"], {"T1059.001"}),
    "lsass_access": (["100150"], {"T1003.001"}),
    "wmi_spawned_shell": (["100160"], {"T1047"}),
}

def jl(p): return [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]
def run(files):
    e = Engine(); out = []
    for f in files:
        for ev in jl(ROOT / f): out += e.process(ev)
    return out

def test_xml_well_formed_and_ids_unique():
    root, rules = load()
    ids = [r.get("id") for r in root.iter("rule")]
    assert len(ids) == len(set(ids))
    assert all(100100 <= int(i) <= 100199 for i in ids)
    for r in root.iter("rule"):
        assert 0 <= int(r.get("level")) <= 16 and r.findtext("description")

@pytest.mark.parametrize("name", REQUIRED)
def test_required_rule_and_mitre(name):
    _, rules = load(); ids, mitre = REQUIRED[name]
    for i in ids:
        assert i in rules, i
        got = {m.text for m in rules[i].iter("id")}
        assert mitre <= got, (i, got)

def test_regexes_compile():
    root, _ = load()
    for f in root.iter("field"):
        re.compile(f.text.replace("(?i)", ""))

def test_if_sid_references_exist():
    root, rules = load()
    for tag in ("if_sid", "if_matched_sid"):
        for x in root.iter(tag): assert x.text in rules

# ---- logic tests (offline simulator) on REAL public EVTX samples ----
def test_real_1102_cleared(): assert "100130" in run(["samples/evtx/DE_1102_security_log_cleared.jsonl"])
def test_real_4104_minidump(): assert "100140" in run(["samples/evtx/Powershell_4104_MiniDumpWriteDump_Lsass.jsonl"])
def test_real_lsass_sysmon10(): assert "100150" in run(["samples/evtx/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.jsonl"])
def test_real_kerberos_spray():
    # sample has 7x 4768 0x00000006 (zero-padded status!) + only 2x 4771 0x18 from 172.16.66.1
    fired = run(["samples/evtx/kerberos_pwd_spray_4771.jsonl"])
    assert "100112" in fired and "100111" not in fired

# ---- synthetic scenarios ----
def test_spray_4625(): assert "100110" in run(["samples/synthetic/spray_4625.jsonl"])
def test_logon_after_failures(): assert "100114" in run(["samples/synthetic/logon_after_failures.jsonl"])
def test_special_privs_skip_system_and_machine():
    e = Engine(); evs = jl(ROOT / "samples/synthetic/special_privs_4672.jsonl")
    res = [e.process(x) for x in evs]
    assert "100120" in res[0] and "100121" in res[0]
    assert "100120" not in res[1] and "100120" not in res[2]
def test_wmi_shell_and_benign_child():
    e = Engine(); evs = jl(ROOT / "samples/synthetic/wmi_shell.jsonl")
    assert "100160" in e.process(evs[0]) and "100160" not in e.process(evs[1])

def test_no_spray_from_brute_single_user():
    assert "100110" not in run(["samples/synthetic/logon_after_failures.jsonl"])

# ---- Suricata ----
def test_suricata_rules_sids_unique():
    lines = [l for l in (ROOT / "suricata/rules/local.rules").read_text().splitlines() if l.startswith("alert")]
    sids = [re.search(r"sid:(\d+);", l).group(1) for l in lines]
    assert len(sids) == len(set(sids)) >= 3
    for l in lines: assert l.count("(") >= 1 and l.rstrip().endswith(")")

def test_pcap_generator(tmp_path):
    import sys; sys.path.insert(0, str(ROOT / "scripts")); import make_pcap
    p = tmp_path / "t.pcap"; n = make_pcap.write(p)
    b = p.read_bytes(); assert b[:4] == bytes.fromhex("d4c3b2a1") and n >= 30
    assert b"SIEMLAB-TEST-7f3a" in b

@pytest.mark.skipif(not shutil.which("docker"), reason="docker not available: run scripts/logtest.sh yourself")
def test_wazuh_logtest_live():
    subprocess.run(["bash", str(ROOT / "scripts/logtest.sh")], check=True)
