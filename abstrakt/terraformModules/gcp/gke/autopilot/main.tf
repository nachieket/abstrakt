provider "google" {
  project = var.project_id
  region  = var.region
}

# VPC (optional, but recommended for isolation and security)
resource "google_compute_network" "vpc" {
  name                    = var.vpc_name
  auto_create_subnetworks = "false"
}

# Subnet (optional, but recommended for network segmentation)
resource "google_compute_subnetwork" "subnet" {
  name          = var.subnet_name
  region        = var.region
  network       = google_compute_network.vpc.name
  ip_cidr_range = var.cidr_range
}

# GKE Autopilot cluster
resource "google_container_cluster" "primary" {
  name     = var.cluster_name
  location = var.region

  # Enable Autopilot mode
  enable_autopilot = true

  # Initial Node count
  initial_node_count       = 1

  # Network configuration (if using VPC and subnet)
  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.subnet.name
}
