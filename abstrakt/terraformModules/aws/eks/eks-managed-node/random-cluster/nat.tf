resource "aws_eip" "nat" {
  vpc = true

  tags = merge(
    var.common_tags,
    {
      Name = "eks-managed-node-eip${var.random_string}"
    }
  )
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public-subnet-a.id

  tags = merge(
    var.common_tags,
    {
      Name = "eks-managed-node-nat-gateway${var.random_string}"
    }
  )

  depends_on = [aws_internet_gateway.igw]
}
