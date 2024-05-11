resource "aws_eip" "nat" {
  vpc = true

  tags = {
    Name = "eks-fargate-eip"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public-subnet-a.id

  tags = {
    Name = "eks-fargate-nat-gateway"
  }

  depends_on = [aws_internet_gateway.igw]
}
