"""Tiny OFFLINE approximation of Wazuh rule matching for local_rules.xml, so logic can be unit-tested
without a manager. Supports: if_group windows (assumed true for win.* events), if_sid, field (regex, negate),
frequency/timeframe with if_matched_sid + same_field/different_field (counting only, no time window),
and if_sid+if_matched_sid sequences. It is NOT Wazuh; real behaviour must be confirmed with wazuh-logtest."""
import re, xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / "wazuh/rules/local_rules.xml"

def load(path=RULES):
    txt = Path(path).read_text()
    root = ET.fromstring("<root>" + txt + "</root>")
    rules = {}
    for r in root.iter("rule"):
        rules[r.get("id")] = r
    return root, rules

def get(ev, dotted):
    cur = ev
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur: return None
        cur = cur[p]
    return cur

def pyre(p):
    return p.replace("(?i)", ""), (re.I if "(?i)" in p else 0)

def fields_ok(rule, ev):
    for f in rule.findall("field"):
        v = get(ev, f.get("name"))
        pat, fl = pyre(f.text)
        m = v is not None and re.search(pat, str(v), fl) is not None
        if f.get("negate") == "yes": m = (v is not None) and not m
        if not m: return False
    return True

class Engine:
    def __init__(self):
        self.root, self.rules = load()
        self.history = defaultdict(list)   # sid -> list of matched events
    def _base(self, rule, ev):
        if rule.find("if_group") is not None and get(ev, "win.system.eventID") is None: return False
        return fields_ok(rule, ev)
    def process(self, ev):
        """Return list of rule ids that fire for this event (most specific last)."""
        fired = []
        simple = [r for r in self.rules.values() if r.get("frequency") is None]
        changed = True
        while changed:
            changed = False
            for r in simple:
                rid = r.get("id")
                if rid in fired: continue
                sid = r.findtext("if_sid")
                if sid and sid not in fired: continue
                if not sid and r.find("if_group") is None: continue
                if self._base(r, ev):
                    fired.append(rid); changed = True
        for r in self.rules.values():
            if r.get("frequency") is None: continue
            need = int(r.get("frequency")); msid = r.findtext("if_matched_sid"); sid = r.findtext("if_sid")
            same = [x.text for x in r.findall("same_field")]; diff = [x.text for x in r.findall("different_field")]
            if sid:   # sequence: current event matches if_sid, prior history of msid
                if sid not in fired: continue
                prior = [e for e in self.history[msid] if all(get(e, s) == get(ev, s) for s in same)]
                if len(prior) >= need: fired.append(r.get("id"))
            elif msid in fired:
                prior = [e for e in self.history[msid] + [ev] if all(get(e, s) == get(ev, s) for s in same)]
                n = len({tuple(get(e, d) for d in diff) for e in prior}) if diff else len(prior)
                if n >= need: fired.append(r.get("id"))
        for rid in fired: self.history[rid].append(ev)
        return fired
