resource "aws_vpc" "main" {

  cidr_block = "10.0.0.0/16"

  # Must be enabled for EFS
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.vpc_name}${var.random_string}"
    }
  )
}
