resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = merge(
    var.common_tags,
    {
      Name = "${var.vpc_name}${var.random_string}"
    }
  )
}
