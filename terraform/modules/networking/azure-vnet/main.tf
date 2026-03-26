###############################################################################
# Azure VNet with NSG Hardening
# Enforces: SC-7 (Boundary Protection), AU-2 (NSG Flow Logs)
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

# -- SC-7: Virtual Network ---------------------------------------------------

resource "azurerm_virtual_network" "main" {
  name                = "${var.name_prefix}-vnet"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.address_space

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-vnet" })
}

# -- SC-7: Public Subnets ----------------------------------------------------

resource "azurerm_subnet" "public" {
  for_each = { for idx, prefix in var.public_subnet_prefixes : "public-${idx}" => prefix }

  name                 = "${var.name_prefix}-${each.key}"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [each.value]
}

# -- SC-7: Private Subnets ---------------------------------------------------

resource "azurerm_subnet" "private" {
  for_each = { for idx, prefix in var.private_subnet_prefixes : "private-${idx}" => prefix }

  name                 = "${var.name_prefix}-${each.key}"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [each.value]
}

# -- SC-7: Network Security Group (deny all inbound by default) ---------------

resource "azurerm_network_security_group" "main" {
  name                = "${var.name_prefix}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  # Explicit deny-all inbound at lowest priority
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Allow intra-VNet traffic
  security_rule {
    name                       = "AllowVNetInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }

  # Allow Azure Load Balancer health probes
  security_rule {
    name                       = "AllowAzureLBInbound"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nsg" })
}

# -- SC-7: NSG associations for public subnets --------------------------------

resource "azurerm_subnet_network_security_group_association" "public" {
  for_each = azurerm_subnet.public

  subnet_id                 = each.value.id
  network_security_group_id = azurerm_network_security_group.main.id
}

# -- SC-7: NSG associations for private subnets -------------------------------

resource "azurerm_subnet_network_security_group_association" "private" {
  for_each = azurerm_subnet.private

  subnet_id                 = each.value.id
  network_security_group_id = azurerm_network_security_group.main.id
}

# -- AU-2: NSG Flow Logs (optional) ------------------------------------------

resource "azurerm_network_watcher_flow_log" "main" {
  count = var.enable_flow_logs && var.flow_log_storage_account_id != null ? 1 : 0

  network_watcher_name = "NetworkWatcher_${var.location}"
  resource_group_name  = "NetworkWatcherRG"
  name                 = "${var.name_prefix}-nsg-flow-log"

  network_security_group_id = azurerm_network_security_group.main.id
  storage_account_id        = var.flow_log_storage_account_id
  enabled                   = true
  version                   = 2

  retention_policy {
    enabled = true
    days    = 365
  }

  dynamic "traffic_analytics" {
    for_each = var.log_analytics_workspace_id != null ? [1] : []
    content {
      enabled               = true
      workspace_id          = var.log_analytics_workspace_id
      workspace_region      = var.location
      workspace_resource_id = var.log_analytics_workspace_id
      interval_in_minutes   = 10
    }
  }

  tags = local.common_tags
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/azure-vnet"
  resource_id    = azurerm_virtual_network.main.id
  control_ids    = ["SC-7", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    address_space    = join(",", var.address_space)
    enable_flow_logs = tostring(var.enable_flow_logs)
    nsg_deny_all     = "true"
  }
}
