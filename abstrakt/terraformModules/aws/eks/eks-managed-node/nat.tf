resource "aws_eip" "nat" {
  vpc = true

  tags = {
    Name = "eks-managed-node-eip"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public-subnet-a.id

  tags = {
    Name = "eks-managed-node-nat-gateway"
  }

  depends_on = [aws_internet_gateway.igw]
}
