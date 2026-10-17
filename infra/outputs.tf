# Values other parts of the infrastructure (and the owner) need. Ids are not secrets.

output "vpc_id" {
  description = "The dedicated VPC."
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "The public subnet the instance will run in."
  value       = aws_subnet.public.id
}

output "instance_security_group_id" {
  description = "Security group with no inbound rules, for the instance."
  value       = aws_security_group.instance.id
}
