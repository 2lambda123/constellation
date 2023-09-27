output "ip" {
  value = var.internal_loadbalancer ? azurerm_lb.loadbalancer.frontend_ip_configuration[0].private_ip_address : azurerm_public_ip.loadbalancer_ip[0].ip_address
}

output "api_server_cert_sans" {
  value = sort(
    concat(
      [
        var.internal_loadbalancer ? azurerm_lb.loadbalancer.frontend_ip_configuration[0].private_ip_address : azurerm_public_ip.loadbalancer_ip[0].ip_address,
        var.internal_loadbalancer ? "" : local.wildcard_lb_dns_name
      ],
    var.custom_endpoint == "" ? [] : [var.custom_endpoint])
  )
}

output "uid" {
  value = local.uid
}

output "initSecret" {
  value     = random_password.initSecret.result
  sensitive = true
}

output "attestationURL" {
  value = var.create_maa ? azurerm_attestation_provider.attestation_provider[0].attestation_uri : ""
}

output "network_security_group_name" {
  value = azurerm_network_security_group.security_group.name
}

output "loadbalancer_name" {
  value = azurerm_lb.loadbalancer.name
}


output "user_assigned_identity_client_id" {
  value = data.azurerm_user_assigned_identity.uaid.client_id
}

output "resource_group" {
  value = var.resource_group
}

output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}
