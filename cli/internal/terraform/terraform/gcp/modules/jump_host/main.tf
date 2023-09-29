terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.83.0"
    }

    google-beta = {
      source  = "hashicorp/google-beta"
      version = "4.83.0"
    }
  }
}


data "google_compute_image" "image_ubuntu" {
  family  = "ubuntu-2204-lts"
  project = "ubuntu-os-cloud"
}

resource "google_compute_instance" "vm_instance" {
  name         = "${var.base_name}-jumphost"
  machine_type = "n2d-standard-4"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = data.google_compute_image.image_ubuntu.self_link
    }
  }

  network_interface {
    subnetwork = var.subnetwork
    access_config {
    }
  }

  service_account {
    scopes = ["compute-ro"]
  }

  labels = var.labels

  metadata = {
    serial-port-enable = "TRUE"
  }

  metadata_startup_script = <<EOF
#!/bin/bash
useradd -m userr
usermod -aG sudo userr
usermod --shell /bin/bash userr
sh -c "echo \"userr:pass\" | chpasswd"

sysctl -w net.ipv4.ip_forward=1
sysctl -p

internal_ip=$(ip route get 8.8.8.8 | grep -oP 'src \K[^ ]+')
%{for port in var.ports~}
iptables -t nat -A PREROUTING -p tcp --dport ${port} -j DNAT --to-destination ${var.lb_internal_ip}:${port}
iptables -t nat -A POSTROUTING -p tcp -d ${var.lb_internal_ip} --dport ${port} -j SNAT --to-source $${internal_ip}
%{endfor~}
EOF

}
