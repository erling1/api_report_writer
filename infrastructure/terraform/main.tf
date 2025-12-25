#Provider 
provider "azurerm" {
  features {}
  subscription_id = "b96bf1ef-708d-4831-bf02-7a7c83e60945"
}

data "azurerm_client_config" "current" {}

# To make key vault globally unique, unsure if this is standard practice 
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

#Resource Group, ACR, AKS
resource "azurerm_resource_group" "johannes_api_rg" {
  name     = "fastapi_rg"
  location = "norwayeast" 
}

resource "azurerm_container_registry" "acr" {
  name                = "fastapijohannes12345acr"
  location            = azurerm_resource_group.johannes_api_rg.location
  resource_group_name = azurerm_resource_group.johannes_api_rg.name
  sku                 = "Basic"
  admin_enabled       = true 
}

resource "azurerm_kubernetes_cluster" "fastapi_aks" {
  name                = "fastapi_aks_cluster"
  location            = azurerm_resource_group.johannes_api_rg.location
  resource_group_name = azurerm_resource_group.johannes_api_rg.name
  dns_prefix          = "fastapi"
  sku_tier            = "Free"

  default_node_pool {
    name            = "default"
    node_count      = 1                
    vm_size         = "Standard_B2s"   
    os_disk_size_gb = 30               
  }  
  
  oidc_issuer_enabled       = true
  workload_identity_enabled = true
  
  identity { 
    type = "SystemAssigned"
  }

}

resource "azurerm_role_assignment" "aks_acr_pull" {
  principal_id         = azurerm_kubernetes_cluster.fastapi_aks.kubelet_identity[0].object_id
  role_definition_name = "AcrPull" 
  scope                = azurerm_container_registry.acr.id 
}



#Github Actions 
resource "azurerm_user_assigned_identity" "github_id" {
  name                = "github-actions-identity"
  location            = azurerm_resource_group.johannes_api_rg.location
  resource_group_name = azurerm_resource_group.johannes_api_rg.name
}

resource "azurerm_federated_identity_credential" "github_trust" {
  name                = "github-actions-trust"
  resource_group_name = azurerm_resource_group.johannes_api_rg.name
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  parent_id           = azurerm_user_assigned_identity.github_id.id
  
  subject             = "repo:erling1/api_report_writer:ref:refs/heads/main"
}

resource "azurerm_role_assignment" "github_contributor" {
  scope                = "/subscriptions/b96bf1ef-708d-4831-bf02-7a7c83e60945"
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.github_id.principal_id
}

# 5. Azure Key Vault 
resource "azurerm_key_vault" "vault" {
  name                        = "kv-fastapi-${random_string.suffix.result}"
  location                    = azurerm_resource_group.johannes_api_rg.location
  resource_group_name         = azurerm_resource_group.johannes_api_rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"
  rbac_authorization_enabled  = true
}



#Helm ESO operator 
provider "helm" {
  kubernetes = {
    host                   = azurerm_kubernetes_cluster.fastapi_aks.kube_config.0.host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.fastapi_aks.kube_config.0.client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.fastapi_aks.kube_config.0.client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.fastapi_aks.kube_config.0.cluster_ca_certificate)
  }
}

# Your Helm resource should look like this (No equals signs for 'set')
resource "helm_release" "external_secrets" {
  name             = "external-secrets"
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  namespace        = "external-secrets"
  create_namespace = true
  version          = "0.9.11"

  set = [{
    name  = "installCRDs"
    value = "true"
  }, {
    name  = "serviceAccount.annotations.azure\\.workload\\.identity/client-id"
    value = azurerm_user_assigned_identity.eso_identity.client_id
  }, {
    name  = "serviceAccount.annotations.azure\\.workload\\.identity/tenant-id"
    value = data.azurerm_client_config.current.tenant_id
  }, {
    name  = "serviceAccount.name"
    value = "eso-service-account"
  }]
}




# 1. The Identity for the Operator itself
resource "azurerm_user_assigned_identity" "eso_identity" {
  name                = "eso-identity"
  location            = azurerm_resource_group.johannes_api_rg.location
  resource_group_name = azurerm_resource_group.johannes_api_rg.name
}

# 2. Grant ESO permission to read your Key Vault
resource "azurerm_role_assignment" "eso_kv_reader" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.eso_identity.principal_id
}

resource "azurerm_role_assignment" "admin_secrets" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}
# 3. Establish the "Trust" (The Federated Credential)
# This tells Azure: "Trust the 'eso-service-account' in the 'external-secrets' namespace"
resource "azurerm_federated_identity_credential" "eso_trust" {
  name                = "eso-aks-trust"
  resource_group_name = azurerm_resource_group.johannes_api_rg.name
  audience            = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.fastapi_aks.oidc_issuer_url
  parent_id           = azurerm_user_assigned_identity.eso_identity.id
  subject             = "system:serviceaccount:external-secrets:eso-service-account"
}
