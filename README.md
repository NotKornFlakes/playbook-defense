# Playbook Defense

[![CI](https://github.com/NotKornFlakes/playbook-defense/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/NotKornFlakes/playbook-defense/actions/workflows/ci.yml)

Turns the post-login playbook from the [Rust telnet honeypot](https://timfletcher.tech/honeypot/)
into protection for a company network on Google Cloud:

1. **Alerts:** 16 Sigma rules, one or more for every step in the playbook table.
2. **Allowlist:** GCP firewall rules so admin ports and telnet only answer approved addresses,
   and IoT devices can only reach the few servers they need.
3. **A trap:** an internal NAS decoy (`nas-backup-01`) that nothing legitimate ever touches,
   so any connection to it is a high-confidence alert.

Everything reads its addresses from one file, `allowlist.yaml`, so the firewall and the alerts
never disagree.

```
allowlist.yaml                 the one file you edit
rules/                         Sigma rules (placeholder addresses, validate as-is)
scripts/apply_allowlist.py     writes build/rules/ with your real addresses
pipelines/gcp_firewall.yml     maps rule fields to GCP firewall log fields
terraform/                     firewall rules + the NAS decoy
```

## The playbook, mapped to alerts

| Playbook step | ATT&CK | Rule | Log source | Level |
|---|---|---|---|---|
| Log in with factory defaults | T1110.001, T1078.001 | 01 Inbound telnet not on allowlist | Firewall | high |
| | | 02 Inbound admin port not on allowlist | Firewall | medium |
| | | 03 Login with a factory-default username | Linux auth | medium |
| Break out of a limited menu / try a router CLI | T1059.008, T1059.004 | 04 Shell spawned from telnet | Process creation | medium |
| Inject a shell into a ping tool | T1059.004 | 05 Command injection in a diagnostic page | Web server | high |
| Look around / find a writable folder | T1082, T1087.001, T1033, T1083 | 06 Device reconnaissance | Process creation | low |
| BusyBox, echo and `SHELL_TEST` checks | T1497.001 | 07 Bot checking for a real shell | Process creation | high |
| Download and run | T1105, T1222.002 | 08 Download from raw IP / run from temp | Process creation | high |
| | | 09 IoT device calls an unapproved destination | Firewall | high |
| | | 10 ...on a known dropper port | Firewall | critical |
| Remove rival bots | T1489 | 11 Mass kill targeting rival malware | Process creation | medium |
| Clean up | T1070.004 | 12 Cleanup of dropped files or history | Process creation | medium |
| Whole playbook | | 13 Telnet attempt + IoT call-out within 10 min | Firewall (correlation) | critical |
| Trap | T1046, T1135 | 14 Anything touched the NAS decoy | Firewall | high |
| | T1110.001, T1021 | 15 Login attempt on the NAS decoy | Firewall | critical |
| | T1105 | 16 NAS decoy tried to connect out | Firewall | critical |

**Start with the firewall rules (01, 02, 09, 10, 13 to 16).** They only need GCP firewall
logs, which `terraform/` turns on for you. The process and auth rules need auditd, an EDR or
syslog from the devices themselves, which many IoT devices can't provide.

## Who should be on the allowlist

The best setup for an office is **one door**:

- **VPN: yes, and make it the main way in.** Staff connect to the VPN from anywhere, and the
  admin ports only trust the VPN's range. Lose a laptop and you revoke one VPN account; you
  don't touch the firewall.
- **Office IP: only if it's static, and only as a fallback.** A dynamic ISP address changes,
  and the next customer who gets it inherits your access. Ask your ISP; if it's dynamic, leave
  it out and use the VPN from the office too.
- **Bastion: on GCP, use Identity-Aware Proxy instead.** IAP needs no public server at all;
  you sign in with your Google account and 2-Step Verification. That's the `35.235.240.0/20`
  line, the same way the honeypot itself is managed.
- **Telnet: nobody.** It's denied for everyone by default, even the allowlist. Turn on
  `allow_legacy_telnet` only while replacing a device that can't do SSH.

If your VPN is GCP Cloud VPN rather than a VPN service with a public address, put the VPN
*client* range (internal addresses) in `vpn_ranges` instead.

## Using it

### 1. Fill in `allowlist.yaml`

Replace every placeholder address. The comments explain each one.

### 2. Build and load the alerts

```sh
pip install sigma-cli pysigma-backend-<your-siem>    # e.g. splunk, elasticsearch, kusto
python3 scripts/apply_allowlist.py                    # writes build/rules/
sigma convert -t <your-siem> -p pipelines/gcp_firewall.yml build/rules/
```

Re-run `apply_allowlist.py` and the conversion every time you change `allowlist.yaml`.

If your SIEM backend doesn't support correlation rules, convert without
`13_correlation_login_then_callout.yml` and build that one as a scheduled search by hand.
It's the only rule that joins two events.

### 3. Apply the firewall and the decoy

```sh
cd terraform
cp terraform.tfvars.example terraform.tfvars          # fill in project, VPC and subnet
ssh-keygen -t ed25519 -f ~/.ssh/decoy_admin -C decoy-admin
terraform init
terraform plan                                        # read it before applying
terraform apply
```

Then tag your instances:
- `managed` on servers whose admin ports the allowlist may reach.
- `iot` on IoT devices or gateways whose outbound traffic is restricted.

`deny-admin-and-telnet-from-anywhere` applies to **every** instance in the VPC the moment
it's created. Only instances tagged `managed` get the allowlist exception, so **tag your
servers `managed` before you apply**. Until it's tagged, a server refuses SSH from everyone,
even through IAP.

### 4. Put the fake shell on the decoy

The decoy runs the same program as the public honeypot, set up the same way. From your
[`rust-telnet-sensor`](https://github.com/NotKornFlakes/rust-telnet-sensor) repo, follow
`deploy/README.md` from the step that installs the program, using `ssh nas-backup-01` in
place of `ssh honeypot`. `host/nftables.conf`, `host/honeypot.service`,
`host/credentials.txt` and `host/honeypot-shell.conf` work unchanged.

The decoy has no public IP. To install packages, its subnet needs Cloud NAT and
`allow_setup_egress = true`, just for that step. Set it back to `false` and apply again
straight afterwards.

### 5. Test the trap

From any internal machine:

```sh
nc -vz 10.20.0.25 445     # should raise rule 14
nc -vz 10.20.0.25 23      # should raise rules 14 and 15
```

GCP firewall logs take a few minutes to arrive. If nothing fires, check the log entries in
Cloud Logging first, then the SIEM's field names against `pipelines/gcp_firewall.yml`.

## Keeping the trap a trap

- **Tell only the security team.** If the decoy appears in a wiki or asset list, it stops being
  a trap, and well-meaning colleagues will trigger it.
- **Add approved scanners to `decoy.ignore_sources`**, or every scheduled vulnerability scan
  becomes a critical alert.
- **Keep the names bland.** The instance is `nas-backup-01` and its network tag is `storage`.
  Nothing in GCP calls it a decoy, because anyone with read access to the project can list
  instances.
- **Check your monitoring policy.** The decoy logs internal IP addresses and anything typed
  into its fake shell. Make sure that's covered by the company's acceptable-use or monitoring
  policy before switching it on.
- **Rule 16 means stop.** The decoy can never connect out. If it tries, shut it down with
  `terraform destroy -target=google_compute_instance.decoy` and investigate.

## What was tested

[CI](.github/workflows/ci.yml) runs on every push and pull request to `master`:

- **Sigma:** `sigma check -i rules/`, which fails on any issue, including an invalid MITRE
  ATT&CK tag, then `apply_allowlist.py` and
  `sigma convert -t splunk -p pipelines/gcp_firewall.yml build/rules/`.
- **Terraform:** `terraform fmt -check`, `terraform init -backend=false` and `terraform validate`.

Also checked by hand:

- The approved-scanner exclusion renders on rules 14 and 15 only.
- Every address in `allowlist.yaml` is a valid CIDR.

Not run: `terraform plan`, which needs your project and credentials. CI also only checks the
placeholder addresses, so once you've filled in `allowlist.yaml`, run these before the first
apply:

```sh
python3 scripts/apply_allowlist.py && sigma check build/rules/
cd terraform && terraform init && terraform plan
```
