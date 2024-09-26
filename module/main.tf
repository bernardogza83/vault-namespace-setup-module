# Create a namespace
resource "vault_namespace" "namespace" {
  path = var.vault_namespace
}

# Enable the AppRole auth backend in the namespace
resource "vault_auth_backend" "approle" {
  type        = "approle"
  description = "AppRole authentication method for ${var.vault_namespace}"
  path        = "approle"
  namespace   = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}

# Enable the LDAP auth backend for the 'organization' organization
resource "vault_ldap_auth_backend" "organization" {
  count     = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  path      = "organization"
  url       = var.ldap_organization_url
  userattr  = var.ldap_organization_user_attr
  userdn    = var.ldap_organization_user_dn
  userfilter = var.ldap_organization_user_filter
  binddn    = var.ldap_organization_bind_dn
  groupattr = var.ldap_organization_group_attr
  groupdn   = var.ldap_organization_group_dn
  groupfilter = var.ldap_organization_group_filter
  bindpass  = var.ldap_organization_password
  token_ttl = 0
  deny_null_bind = true
  max_page_size = 0
  token_max_ttl = 0
  namespace = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}

# Enable the LDAP auth backend for 'organization-sp'
resource "vault_ldap_auth_backend" "organization_sp" {
  count     = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  path      = "organization-sp"
  url       = var.ldap_organization_sp_url
  userattr  = var.ldap_organization_sp_user_attr
  userdn    = var.ldap_organization_sp_user_dn
  userfilter = var.ldap_organization_sp_user_filter
  binddn    = var.ldap_organization_sp_bind_dn
  groupattr = var.ldap_organization_sp_group_attr
  groupdn   = var.ldap_organization_sp_group_dn
  groupfilter = var.ldap_organization_sp_group_filter
  bindpass  = var.ldap_organization_sp_password
  token_ttl = 0
  deny_null_bind = true
  max_page_size = 0
  token_max_ttl = 0
  namespace = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}

# Enable the OIDC (OpenID Connect) auth backend
resource "vault_jwt_auth_backend" "oidc" {
  count      = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  type       = "oidc"
  description = "OIDC authentication method for ${var.vault_namespace}"
  path       = "oidc"
  bound_issuer = var.oidc_organization_bound_issuer
  default_role = var.oidc_organization_default_role
  oidc_client_id = var.oidc_organization_client_id
  oidc_client_secret = var.oidc_organization_client_secret
  oidc_discovery_url = var.oidc_organization_oidc_discovery_url
  namespace   = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}

# Configure an OIDC role for JWT authentication
resource "vault_jwt_auth_backend_role" "role" {
  count           = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  backend         = "oidc"
  role_name       = "organization"
  groups_claim    = var.oidc_organization_groups_claim
  role_type       = "oidc"
  allowed_redirect_uris = var.oidc_organization_allowed_redirect_uris
  user_claim      = var.oidc_organization_user_claim
  oidc_scopes     = var.oidc_organization_oidc_scopes
  namespace       = vault_namespace.namespace.path
  depends_on      = [vault_jwt_auth_backend.oidc]
}

# Define the admin policy for the namespace
resource "vault_policy" "admin_policy" {
  count     = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  name      = "vault-admin"
  policy    = file("${path.module}/Policies/admin.hcl")
  namespace = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}

# Create an LDAP group for Vault admins and attach the admin policy
resource "vault_ldap_auth_backend_group" "vault_admin" {
  count     = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  groupname = var.ldap_organization_vault_admin_group
  policies  = ["vault-admin"]
  backend   = "organization"
  depends_on  = [vault_ldap_auth_backend.organization]
  namespace = vault_namespace.namespace.path
}

# Create an external identity group for OIDC and attach the admin policy
resource "vault_identity_group" "organization_oidc_external" {
  count     = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  name     = "vault-admin"
  type     = "external"
  policies = ["vault-admin"]
  depends_on  = [vault_jwt_auth_backend_role.role]
  metadata = {
    version = "2"
  }
  namespace = vault_namespace.namespace.path
}

# Create an alias for the OIDC group in the namespace
resource "vault_identity_group_alias" "group-alias" {
  count          = var.vault_namespace == var.vault_root_namespace ? 1 : 0
  name           = var.oidc_organization_vault_admin_group
  mount_accessor = vault_jwt_auth_backend.oidc[count.index].accessor
  canonical_id   = vault_identity_group.organization_oidc_external[count.index].id
  namespace      = vault_namespace.namespace.path
}

# Enable the KV version 1 secret backend in the namespace
resource "vault_mount" "kv1" {
  path        = "kv-v1"
  type        = "kv"
  description = "Key-Value version 1 secret engine for ${var.vault_namespace}"
  options     = {
    version = "1"
  }
  namespace   = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}

# Enable the KV version 2 secret backend in the namespace
resource "vault_mount" "kv2" {
  path        = "kv-v2"
  type        = "kv"
  description = "Key-Value version 2 secret engine for ${var.vault_namespace}"
  options     = {
    version = "2"
  }
  namespace   = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}

# Enable the Transit secret engine in the namespace
resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "Transit secret engine for ${var.vault_namespace}"
  namespace   = vault_namespace.namespace.path
  depends_on  = [vault_namespace.namespace]
}
