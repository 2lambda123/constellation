output "ip" {
  value = var.internal_loadbalancer ? aws_lb.front_end.dns_name : aws_lb.front_end.dns_name
}

output "api_server_cert_sans" {
  value = sort(
    concat(
      [
        var.internal_loadbalancer ? aws_lb.front_end.dns_name : aws_eip.lb[var.zone].public_ip,
        local.wildcard_lb_dns_name
      ],
  var.custom_endpoint == "" ? [] : [var.custom_endpoint]))
}

output "uid" {
  value = local.uid
}

output "initSecret" {
  value     = random_password.initSecret.result
  sensitive = true
}
