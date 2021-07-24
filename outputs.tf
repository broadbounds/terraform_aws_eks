output "bastion_host_1_public_ip" {  
  value = "${aws_eip.bastion_elastic_ip_1.public_ip}"
}

output "bastion_host_1_private_ip" {  
  value = "${aws_instance.bastion_host_1.private_ip}"
}

output "bastion_host_2_public_ip" {  
  value = "${aws_eip.bastion_elastic_ip_2.public_ip}"
}

output "bastion_host_2_private_ip" {  
  value = "${aws_instance.bastion_host_2.private_ip}"
}
