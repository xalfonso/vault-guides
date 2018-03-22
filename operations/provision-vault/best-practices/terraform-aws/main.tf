module "ssh_keypair_aws_override" {
  source = "github.com/hashicorp-modules/ssh-keypair-aws?ref=f-refactor"

  name = "${var.name}-override"
}

module "consul_auto_join_instance_role" {
  source = "github.com/hashicorp-modules/consul-auto-join-instance-role-aws?ref=f-refactor"

  name = "${var.name}"
}

resource "random_id" "consul_encrypt" {
  byte_length = 16
}

module "consul_tls_self_signed_cert" {
  source = "github.com/hashicorp-modules/tls-self-signed-cert?ref=f-refactor"

  name                  = "${var.name}-consul"
  validity_period_hours = "24"
  ca_common_name        = "hashicorp.com"
  organization_name     = "HashiCorp Inc."
  common_name           = "hashicorp.com"
  dns_names             = ["*.node.consul", "*.service.consul"]
  ip_addresses          = ["0.0.0.0", "127.0.0.1"]
}

module "vault_tls_self_signed_cert" {
  source = "github.com/hashicorp-modules/tls-self-signed-cert?ref=f-refactor"

  name                  = "${var.name}-vault"
  validity_period_hours = "24"
  ca_common_name        = "hashicorp.com"
  organization_name     = "HashiCorp Inc."
  common_name           = "hashicorp.com"
  dns_names             = ["*.node.consul", "*.service.consul"]
  ip_addresses          = ["0.0.0.0", "127.0.0.1"]
}

data "template_file" "bastion_user_data" {
  template = "${file("${path.module}/../../templates/best-practices-bastion-systemd.sh.tpl")}"

  vars = {
    name            = "${var.name}"
    provider        = "${var.provider}"
    local_ip_url    = "${var.local_ip_url}"
    consul_encrypt  = "${random_id.consul_encrypt.b64_std}"
    consul_ca_crt   = "${module.consul_tls_self_signed_cert.ca_cert_pem}"
    consul_leaf_crt = "${module.consul_tls_self_signed_cert.leaf_cert_pem}"
    consul_leaf_key = "${module.consul_tls_self_signed_cert.leaf_private_key_pem}"
    vault_ca_crt    = "${module.vault_tls_self_signed_cert.ca_cert_pem}"
    vault_leaf_crt  = "${module.vault_tls_self_signed_cert.leaf_cert_pem}"
    vault_leaf_key  = "${module.vault_tls_self_signed_cert.leaf_private_key_pem}"
  }
}

module "network_aws" {
  source = "github.com/hashicorp-modules/network-aws?ref=f-refactor"

  name              = "${var.name}"
  vpc_cidr          = "${var.vpc_cidr}"
  vpc_cidrs_public  = "${var.vpc_cidrs_public}"
  nat_count         = "${var.nat_count}"
  vpc_cidrs_private = "${var.vpc_cidrs_private}"
  release_version   = "${var.bastion_release_version}"
  consul_version    = "${var.bastion_consul_version}"
  vault_version     = "${var.bastion_vault_version}"
  os                = "${var.bastion_os}"
  os_version        = "${var.bastion_os_version}"
  bastion_count     = "${var.bastion_count}"
  instance_profile  = "${module.consul_auto_join_instance_role.instance_profile_id}" # Override instance_profile
  instance_type     = "${var.bastion_instance_type}"
  user_data         = "${data.template_file.bastion_user_data.rendered}" # Override user_data
  ssh_key_name      = "${module.ssh_keypair_aws_override.name}"
  ssh_key_override  = "true"
  tags              = "${var.network_tags}"
}

data "template_file" "consul_user_data" {
  template = "${file("${path.module}/../../templates/best-practices-consul-systemd.sh.tpl")}"

  vars = {
    name             = "${var.name}"
    provider         = "${var.provider}"
    local_ip_url     = "${var.local_ip_url}"
    consul_bootstrap = "${length(module.network_aws.subnet_private_ids)}"
    consul_encrypt   = "${random_id.consul_encrypt.b64_std}"
    consul_ca_crt    = "${module.consul_tls_self_signed_cert.ca_cert_pem}"
    consul_leaf_crt  = "${module.consul_tls_self_signed_cert.leaf_cert_pem}"
    consul_leaf_key  = "${module.consul_tls_self_signed_cert.leaf_private_key_pem}"
  }
}

module "consul_aws" {
  source = "github.com/hashicorp-modules/consul-aws?ref=f-refactor"

  name             = "${var.name}" # Must match network_aws module name for Consul Auto Join to work
  vpc_id           = "${module.network_aws.vpc_id}"
  vpc_cidr         = "${module.network_aws.vpc_cidr_block}"
  subnet_ids       = "${module.network_aws.subnet_private_ids}"
  release_version  = "${var.consul_release_version}"
  consul_version   = "${var.consul_version}"
  os               = "${var.consul_os}"
  os_version       = "${var.consul_os_version}"
  count            = "${var.consul_count}"
  instance_profile = "${module.consul_auto_join_instance_role.instance_profile_id}" # Override instance_profile
  instance_type    = "${var.consul_instance_type}"
  user_data        = "${data.template_file.consul_user_data.rendered}" # Custom user_data
  ssh_key_name     = "${module.ssh_keypair_aws_override.name}"
  tags             = "${var.consul_tags}"
}

data "template_file" "vault_user_data" {
  template = "${file("${path.module}/../../templates/best-practices-vault-systemd.sh.tpl")}"

  vars = {
    name            = "${var.name}"
    provider        = "${var.provider}"
    local_ip_url    = "${var.local_ip_url}"
    consul_encrypt  = "${random_id.consul_encrypt.b64_std}"
    consul_ca_crt   = "${module.consul_tls_self_signed_cert.ca_cert_pem}"
    consul_leaf_crt = "${module.consul_tls_self_signed_cert.leaf_cert_pem}"
    consul_leaf_key = "${module.consul_tls_self_signed_cert.leaf_private_key_pem}"
    vault_ca_crt    = "${module.vault_tls_self_signed_cert.ca_cert_pem}"
    vault_leaf_crt  = "${module.vault_tls_self_signed_cert.leaf_cert_pem}"
    vault_leaf_key  = "${module.vault_tls_self_signed_cert.leaf_private_key_pem}"
  }
}

module "vault_aws" {
  source = "github.com/hashicorp-modules/vault-aws?ref=f-refactor"

  name             = "${var.name}" # Must match network_aws module name for Consul Auto Join to work
  vpc_id           = "${module.network_aws.vpc_id}"
  vpc_cidr         = "${module.network_aws.vpc_cidr_block}"
  subnet_ids       = "${module.network_aws.subnet_private_ids}"
  release_version  = "${var.vault_release_version}"
  vault_version    = "${var.vault_version}"
  consul_version   = "${var.consul_version}"
  os               = "${var.vault_os}"
  os_version       = "${var.vault_os_version}"
  count            = "${var.vault_count}"
  instance_profile = "${module.consul_auto_join_instance_role.instance_profile_id}" # Override instance_profile
  instance_type    = "${var.vault_instance_type}"
  user_data        = "${data.template_file.vault_user_data.rendered}" # Custom user_data
  ssh_key_name     = "${module.ssh_keypair_aws_override.name}"
  tags             = "${var.vault_tags}"
}