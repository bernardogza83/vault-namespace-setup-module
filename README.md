# Vault Namespace setup Terraform Module

## Overview

This Terraform module configures Vault with various resources, including namespaces, AppRole auth backend, LDAP auth backend, OIDC auth backend, policies and secret engines.

## Requirements

* Vault server
* Terraform

## Usage

1. Copy and paste the contents of this file into a new Terraform configuration file (e.g., `main.tf`).
2. Update the variables and locals to match your specific use case.
3. Run `terraform init` to initialize the Terraform working directory.
4. Run `terraform apply` to apply the configuration.

## Variables

* `vault_namespace`: The namespace to create and configure.
* `vault_root_namespace`: The root namespace.
* `ldap_organization_url`: The LDAP URL for the 'organization' organization.
* `ldap_organization_user_attr`: The LDAP user attribute for the 'organization' organization.
* `ldap_organization_user_dn`: The LDAP user DN for the 'organization' organization.
* `ldap_organization_user_filter`: The LDAP user filter for the 'organization' organization.
* `ldap_organization_bind_dn`: The LDAP bind DN for the 'organization' organization.
* `ldap_organization_group_attr`: The LDAP group attribute for the 'organization' organization.
* `ldap_organization_group_dn`: The LDAP group DN for the 'organization' organization.
* `ldap_organization_group_filter`: The LDAP group filter for the 'organization' organization.
* `ldap_organization_password`: The LDAP password for the 'organization' organization.
* `oidc_organization_bound_issuer`: The OIDC bound issuer for the 'organization' organization.
* `oidc_organization_default_role`: The OIDC default role for the 'organization' organization.
* `oidc_organization_client_id`: The OIDC client ID for the 'organization' organization.
* `oidc_organization_client_secret`: The OIDC client secret for the 'organization' organization.
* `oidc_organization_oidc_discovery_url`: The OIDC discovery URL for the 'organization' organization.
* `oidc_organization_groups_claim`: The OIDC groups claim for the 'organization' organization.
* `oidc_organization_allowed_redirect_uris`: The OIDC allowed redirect URIs for the 'organization' organization.
* `oidc_organization_user_claim`: The OIDC user claim for the 'organization' organization.
* `oidc_organization_oidc_scopes`: The OIDC scopes for the 'organization' organization.

## Resources

* `vault_namespace`: Creates a namespace.
* `vault_auth_backend`: Enables the AppRole auth backend in the namespace.
* `vault_ldap_auth_backend`: Enables the LDAP auth backend for the 'organization' organization.
* `vault_jwt_auth_backend`: Enables the OIDC auth backend.
* `vault_jwt_auth_backend_role`: Configures an OIDC role for JWT authentication.
* `vault_policy`: Defines the admin policy for the namespace.
* `vault_ldap_auth_backend_group`: Creates an LDAP group for Vault admins and attaches the admin policy.
* `vault_identity_group`: Creates an external identity group for OIDC and attaches the admin policy.
* `vault_identity_group_alias`: Creates an alias for the OIDC group in the namespace.
* `vault_mount`: Enables the KV version 1 secret backend, KV version 2 secret backend, and Transit secret engine in the namespace.