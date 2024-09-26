variable "vault_namespace" {
  description = "Namespace to create within Vault"
  type        = string
}

variable "vault_root_namespace" {
  description = "Name of organization root namespace"
  type        = string
  default     = "organization-international"
}

variable "ldap_organization_url" {
  description = "organization ldap url"
  type        = string
}

variable "ldap_organization_user_dn" {
  description = "organization ldap user dn"
  type        = string
}

variable "ldap_organization_user_filter" {
  description = "organization ldap user filter"
  type        = string
}

variable "ldap_organization_user_attr" {
  description = "organization ldap user attr"
  type        = string
}

variable "ldap_organization_group_dn" {
  description = "organization ldap group dn"
  type        = string
}

variable "ldap_organization_group_attr" {
  description = "organization ldap group attr"
  type        = string
}


variable "ldap_organization_group_filter" {
  description = "organization ldap group filter"
  type        = string
}

variable "ldap_organization_bind_dn" {
  description = "organization ldap bind dn"
  type        = string
}

variable "ldap_organization_password" {
  description = "organization ldap password"
  type        = string
}

variable "ldap_organization_vault_admin_group" {
  description = "organization vault admin group"
  type        = string
}

variable "ldap_organization_sp_url" {
  description = "organization sp ldap url"
  type        = string
}

variable "ldap_organization_sp_user_dn" {
  description = "organization sp ldap user dn"
  type        = string
}

variable "ldap_organization_sp_user_filter" {
  description = "organization sp ldap user filter"
  type        = string
}

variable "ldap_organization_sp_user_attr" {
  description = "organization sp ldap user attr"
  type        = string
}

variable "ldap_organization_sp_bind_dn" {
  description = "organization sp ldap bind dn"
  type        = string
}

variable "ldap_organization_sp_group_dn" {
  description = "organization sp ldap group dn"
  type        = string
}

variable "ldap_organization_sp_group_attr" {
  description = "organization sp ldap group attr"
  type        = string
}

variable "ldap_organization_sp_group_filter" {
  description = "organization sp ldap group filter"
  type        = string
}

variable "ldap_organization_sp_password" {
  description = "organization sp ldap password"
  type        = string
}

variable "oidc_organization_bound_issuer" {
  description = "organization oidc bound issuer"
  type        = string
}

variable "oidc_organization_default_role" {
  description = "organization oidc default role"
  type        = string
}

variable "oidc_organization_client_id" {
  description = "organization oidc client id"
  type        = string
}

variable "oidc_organization_client_secret" {
  description = "organization oidc client id"
  type        = string
}

variable "oidc_organization_oidc_discovery_url" {
  description = "organization oidc discpvery url"
  type        = string
}

variable "oidc_organization_groups_claim" {
  description = "organization oidc groups claim"
  type        = string
}

variable "oidc_organization_user_claim" {
  description = "organization oidc user claim"
  type        = string
}

variable "oidc_organization_allowed_redirect_uris" {
  type        = list(string)
  description = "allowed_redirect_uris"
}

variable "oidc_organization_oidc_scopes" {
  type        = list(string)
  description = "oidc_scopes"
}

variable "oidc_organization_vault_admin_group" {
  description = "organization vault admin group"
  type        = string
}