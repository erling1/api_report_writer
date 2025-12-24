
provider "azurerm" {
  features {}
  subscription_id = "b96bf1ef-708d-4831-bf02-7a7c83e60945"
}

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
  sku_tier            = "Free" # Explicitly use the Free Tier (no management fee)

  default_node_pool {
    name            = "default"
    node_count      = 1                
    vm_size         = "Standard_B2s"   
    os_disk_size_gb = 30               
  }  
  
  identity { 
    type = "SystemAssigned"
  }
}

resource "azurerm_role_assignment" "aks_acr_pull" {
  principal_id         = azurerm_kubernetes_cluster.fastapi_aks.kubelet_identity[0].object_id
  role_definition_name = "AcrPull" 
  scope                = azurerm_container_registry.acr.id 

  depends_on = [
    azurerm_kubernetes_cluster.fastapi_aks,
    azurerm_container_registry.acr
  ]
}
