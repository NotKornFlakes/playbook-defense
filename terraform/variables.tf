variable "project_id" {
  description = "The Google Cloud project that holds the company network."
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "network" {
  description = "Name of the EXISTING company VPC these rules attach to."
  type        = string
}

variable "decoy_subnetwork" {
  description = "Name of the EXISTING subnet the NAS decoy joins. decoy.ip in allowlist.yaml must be inside it."
  type        = string
}

variable "allowlist_file" {
  description = "Path to the shared allowlist, also used to build the Sigma rules."
  type        = string
  default     = "../allowlist.yaml"
}

variable "managed_tag" {
  description = "Network tag on servers whose admin ports the allowlist may reach."
  type        = string
  default     = "managed"
}

variable "iot_tag" {
  description = "Network tag on IoT devices or gateways whose outbound traffic is restricted."
  type        = string
  default     = "iot"
}

variable "decoy_tag" {
  description = "Network tag for the decoy. Keep it bland: anyone who can list instances sees it."
  type        = string
  default     = "storage"
}

variable "decoy_machine_type" {
  type    = string
  default = "e2-micro"
}

variable "ssh_public_key_path" {
  description = "Public half of the SSH key used only for the decoy."
  type        = string
  default     = "~/.ssh/decoy_admin.pub"
}

variable "allow_legacy_telnet" {
  description = "Allow telnet from the allowlist, for a legacy device that can't do SSH. Leave false if you can."
  type        = bool
  default     = false
}

variable "allow_setup_egress" {
  description = "Let the decoy connect out to install packages (needs Cloud NAT on its subnet). Only true during setup."
  type        = bool
  default     = false
}
