###############################################################################
# Azure VM Hardening
# Enforces: SC-28 (Disk Encryption), CM-6 (Secure Config), IA-2 (Identity)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-28, CM-6, IA-2: Hardened Linux VM ------------------------------------

resource "azurerm_linux_virtual_machine" "main" {
  name                = "${var.name_prefix}-vm"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = var.size

  network_interface_ids = [azurerm_network_interface.main.id]

  admin_username                  = var.admin_username
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  # SC-28: Encryption at host covers all VM disks
  encryption_at_host_enabled = true

  os_disk {
    name                 = "${var.name_prefix}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = var.source_image_reference.publisher
    offer     = var.source_image_reference.offer
    sku       = var.source_image_reference.sku
    version   = var.source_image_reference.version
  }

  # IA-2: System-assigned managed identity
  identity {
    type = "SystemAssigned"
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-vm" })
}

# -- Network interface --------------------------------------------------------

resource "azurerm_network_interface" "main" {
  name                = "${var.name_prefix}-nic"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nic" })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/azure-vm"
  resource_id    = azurerm_linux_virtual_machine.main.id
  control_ids    = ["SC-28", "CM-6", "IA-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    encryption_at_host = "true"
    managed_identity   = "SystemAssigned"
    password_auth      = "disabled"
  }
}
