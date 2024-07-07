resource "azurerm_resource_group" "rg" {
  location = var.resource_group_location
  name     = var.resource_group_name

  tags = var.common_tags
}

locals {
  oscheck = {
    mac   = can(file("/System/Library/CoreServices/SystemVersion.plist"))
    linux = can(file("/etc/os-release"))
  }
}

resource "azurerm_kubernetes_cluster" "k8s" {
  location            = var.resource_group_location
  name                = var.cluster_name
  resource_group_name = var.resource_group_name
  dns_prefix          = var.dns_prefix

  identity {
    type = "SystemAssigned"
  }

  default_node_pool {
    name       = "agentpool"
    vm_size    = var.vm_size
    node_count = var.node_count

    # Use ephemeral OS disk
    # os_disk_type = "Ephemeral"
  }

  linux_profile {
    admin_username = var.cluster_username

    ssh_key {
      key_data = local.oscheck.mac ? jsondecode(azapi_resource_action.ssh_public_key_gen.output).publicKey : jsondecode(jsonencode(azapi_resource_action.ssh_public_key_gen.output)).publicKey
    }
  }

#   linux_profile {
#     admin_username = var.cluster_username
#
#     ssh_key {
# #       key_data = jsondecode(azapi_resource_action.ssh_public_key_gen.output).publicKey
#         key_data = jsondecode(jsonencode(azapi_resource_action.ssh_public_key_gen.output)).publicKey
#
#     }
#   }

  network_profile {
    network_plugin    = "kubenet"
    load_balancer_sku = "standard"
  }

  tags = var.common_tags
}
