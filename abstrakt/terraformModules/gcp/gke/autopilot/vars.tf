variable "cluster_name" {
  default = "random-autopilot-cluster"
}

variable "vpc_name" {
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
