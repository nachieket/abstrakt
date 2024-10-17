resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.common_tags,
    {
      Name = "eks-managed-node-igw${var.random_string}"
    }
  )
}
