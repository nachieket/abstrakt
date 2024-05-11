variable "region" {
  default = "eu-west-2"
}

variable "vpc_name" {
  default = "random-eks-fargate-vpc"
}

variable "cluster_name" {
  default = "random-eks-fargate-cluster"
}

variable "cluster_version" {
  default = "1.28"
}

variable "common_tags" {
  default =  {
    "cstag-owner": "njoshi02",
    "cstag-product": "Falcon",
    "cstag-accounting": "dev",
    "cstag-department": "Sales - 310000",
    "cstag-business": "Sales"
  }
}

variable "public_access_cidrs" {
  default = "0.0.0.0/0"
}
