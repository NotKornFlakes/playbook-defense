# Company firewall allowlist, IoT egress limits and the internal NAS decoy, on Google Cloud.
#
# Every address comes from ../allowlist.yaml, the same file the Sigma rules are built from,
# so the firewall and the alerts never disagree. Every rule has logging on, because GCP only
# writes a firewall log entry for connections that match a rule with logging turned on, and
# those log entries are what the alerts read.
#
# GCP firewall priorities: the LOWER number wins.
#   500  NAS decoy rules (must beat any broad "allow-internal" rule you already have)
#   900  allowlist and approved IoT destinations
#   1000 deny-by-default for admin ports, telnet and IoT egress

terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

locals {
  allow = yamldecode(file(var.allowlist_file))

  # Missing or empty lists in the YAML count as "none".
  admin_sources = flatten([
    for key in ["vpn_ranges", "office_ips", "bastion_ips"] :
    try(local.allow[key], null) == null ? [] : local.allow[key]
  ])

  telnet_ports = ["23", "2323"]

  # Telnet only joins the allowlisted ports if you explicitly need it for a legacy device.
  allowlisted_ports = concat(
    local.allow.admin_ports,
    var.allow_legacy_telnet ? local.telnet_ports : [],
  )

  # Ports the NAS decoy answers on. Only telnet (23) runs the fake shell. The rest have
  # nothing listening, but every connection attempt is still logged by the VPC firewall,
  # which is all the alert needs. They're the ports a real NAS opens: FTP, web admin,
  # rpcbind, NetBIOS, SMB, AFP, rsync, NFS and the 5000/5001 admin pages many NAS use.
  decoy_tripwire_ports = ["21", "23", "80", "111", "139", "443", "445", "548", "873", "2049", "5000", "5001"]

  iap_range  = "35.235.240.0/20"
  admin_user = "decoyadmin"
}

# ---------------------------------------------------------------------------------------------
# 1. Inbound: admin ports only from the allowlist
# ---------------------------------------------------------------------------------------------

resource "google_compute_firewall" "admin_from_allowlist" {
  name          = "allow-admin-from-allowlist"
  description   = "Admin ports, only from the VPN, static office IPs and the bastion/IAP range."
  network       = var.network
  direction     = "INGRESS"
  priority      = 900
  source_ranges = local.admin_sources
  target_tags   = [var.managed_tag]

  allow {
    protocol = "tcp"
    ports    = local.allowlisted_ports
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  lifecycle {
    precondition {
      condition     = length(local.admin_sources) > 0
      error_message = "allowlist.yaml: vpn_ranges, office_ips and bastion_ips are all empty, which would lock everyone out of the admin ports."
    }
  }
}

# Applies to every instance in the network, so a forgotten VM can't leave a door open.
resource "google_compute_firewall" "deny_admin_from_anywhere" {
  name          = "deny-admin-and-telnet-from-anywhere"
  description   = "Everything not on the allowlist is refused on admin ports and telnet, and logged."
  network       = var.network
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "tcp"
    ports    = distinct(concat(local.allow.admin_ports, local.telnet_ports))
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Nothing in the company should be telnetting out either. Unused telnet clients are how a
# compromised device spreads to the next one.
resource "google_compute_firewall" "deny_telnet_egress" {
  count = var.allow_legacy_telnet ? 0 : 1

  name               = "deny-telnet-egress"
  network            = var.network
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "tcp"
    ports    = local.telnet_ports
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ---------------------------------------------------------------------------------------------
# 2. Outbound: IoT devices may only reach the servers they need
# ---------------------------------------------------------------------------------------------

resource "google_compute_firewall" "iot_egress_allowed" {
  name               = "allow-iot-egress-approved"
  description        = "The few destinations IoT devices genuinely need."
  network            = var.network
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = local.allow.iot.allowed_destinations
  target_tags        = [var.iot_tag]

  dynamic "allow" {
    for_each = { for proto, ports in local.allow.iot.allowed_ports : proto => ports if length(ports) > 0 }
    content {
      protocol = allow.key
      ports    = allow.value
    }
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Every dropper on the honeypot had to fetch its payload from the internet. This blocks it,
# and the log entry is what the IoT outbound alerts read.
resource "google_compute_firewall" "iot_egress_deny" {
  name               = "deny-iot-egress-everything-else"
  network            = var.network
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [var.iot_tag]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ---------------------------------------------------------------------------------------------
# 3. The NAS decoy
# ---------------------------------------------------------------------------------------------

# The tripwire: internal machines can reach the NAS ports, and every attempt is logged.
resource "google_compute_firewall" "decoy_tripwire" {
  name          = "${local.allow.decoy.name}-allow-internal"
  network       = var.network
  direction     = "INGRESS"
  priority      = 500
  source_ranges = local.allow.decoy.internal_ranges
  target_tags   = [var.decoy_tag]

  allow {
    protocol = "tcp"
    ports    = local.decoy_tripwire_ports
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Admin access to the decoy only through an IAP tunnel, like the public honeypot.
resource "google_compute_firewall" "decoy_admin_from_iap" {
  name          = "${local.allow.decoy.name}-admin-iap"
  network       = var.network
  direction     = "INGRESS"
  priority      = 500
  source_ranges = [local.iap_range]
  target_tags   = [var.decoy_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# Any other port or protocol is refused, but still logged, so the alert sees the whole scan.
resource "google_compute_firewall" "decoy_deny_other_ingress" {
  name          = "${local.allow.decoy.name}-deny-other"
  network       = var.network
  direction     = "INGRESS"
  priority      = 600
  source_ranges = ["0.0.0.0/0"]
  target_tags   = [var.decoy_tag]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# The decoy never starts a connection. Firewall rules track connections, so replies to
# visitors still get out. Anything this logs is a reason to shut the decoy down.
resource "google_compute_firewall" "decoy_deny_egress" {
  count = var.allow_setup_egress ? 0 : 1

  name               = "${local.allow.decoy.name}-deny-egress"
  network            = var.network
  direction          = "EGRESS"
  priority           = 500
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [var.decoy_tag]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# No public IP and no service account, so it has no Google Cloud permissions at all.
# The instance name becomes the hostname, which is what makes it look like a NAS.
resource "google_compute_instance" "decoy" {
  #checkov:skip=CKV_GCP_38:Google-managed encryption is enough, and the decoy holds no secrets
  name         = local.allow.decoy.name
  machine_type = var.decoy_machine_type
  zone         = var.zone
  tags         = [var.decoy_tag]

  boot_disk {
    auto_delete = true
    initialize_params {
      image = "debian-cloud/debian-13"
      size  = 20
    }
  }

  network_interface {
    subnetwork = var.decoy_subnetwork
    network_ip = local.allow.decoy.ip
    stack_type = "IPV4_ONLY"
    # No access_config block: no public IP.
  }

  metadata = {
    block-project-ssh-keys = "TRUE"
    enable-oslogin         = "FALSE"
    serial-port-enable     = "FALSE"
    ssh-keys               = "${local.admin_user}:${trimspace(file(pathexpand(var.ssh_public_key_path)))}"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

output "decoy_ip" {
  value = google_compute_instance.decoy.network_interface[0].network_ip
}

output "ssh_config" {
  description = "Add this to ~/.ssh/config, then `ssh <decoy name>` connects through the IAP tunnel."
  value       = <<-EOT
    Host ${local.allow.decoy.name}
      User ${local.admin_user}
      IdentityFile ${trimsuffix(pathexpand(var.ssh_public_key_path), ".pub")}
      IdentitiesOnly yes
      ProxyCommand gcloud compute start-iap-tunnel ${local.allow.decoy.name} %p --listen-on-stdin --project=${var.project_id} --zone=${var.zone} --verbosity=warning
  EOT
}
