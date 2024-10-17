variable "cluster_name" {
  default = "random-autopilot-cluster"
}

variable "vpc_network" {
  default = "random-autopilot"
}

variable "subnet_name" {
  default = "random-autopilot-subnet"
}

variable "project_id" {
  description = "project id"
}

variable "region" {
  default = "eu-west-2"
}

variable "cidr_range" {
  default = "10.10.0.0/24"
}

variable "machine_type" {
  default = "n4-standard-16"
}

variable "gke_num_nodes" {
  default     = 2
  description = "number of gke nodes"
}

variable "version_prefix" {
  default = "1.27."
}

variable "gke_username" {
  default     = ""
  description = "gke username"
}

variable "gke_password" {
  default     = ""
  description = "gke password"
}
