package authz

import (
	"regexp"
	"strings"
)

// System permissions in a tenant. Tenants may add their own <resource_type>:<action> permissions.
const (
	PermAppAccess      = "app:access"
	PermAppManage      = "app:manage"
	PermTenantManage   = "tenant:manage"
	PermMemberManage   = "member:manage"
	PermGroupManage    = "group:manage"
	PermRoleManage     = "role:manage"
	PermPolicyManage   = "policy:manage"
	PermResourceManage = "resource:manage"
	PermInviteManage   = "invite:manage"
	PermAuditRead      = "audit:read"
	PermAuthzSimulate  = "authz:simulate"
	PermServiceAccount = "service_account:manage"
)

// Read-only counterparts of the management permissions (ADR-0048): each lets the management API read what the
// matching :manage permission changes, and nothing else. A :manage permission also allows the reads.
const (
	PermAppRead            = "app:read"
	PermTenantRead         = "tenant:read"
	PermMemberRead         = "member:read"
	PermGroupRead          = "group:read"
	PermRoleRead           = "role:read"
	PermPolicyRead         = "policy:read"
	PermResourceRead       = "resource:read"
	PermInviteRead         = "invite:read"
	PermServiceAccountRead = "service_account:read"
)

// SystemPermissions lists the built-in catalogue.
var SystemPermissions = []string{PermAppAccess, PermAppManage, PermTenantManage, PermMemberManage, PermGroupManage, PermRoleManage,
	PermPolicyManage, PermResourceManage, PermInviteManage, PermAuditRead, PermAuthzSimulate, PermServiceAccount,
	PermAppRead, PermTenantRead, PermMemberRead, PermGroupRead, PermRoleRead, PermPolicyRead, PermResourceRead, PermInviteRead,
	PermServiceAccountRead}

// ReadPermissions lists the read-only system permissions.
var ReadPermissions = []string{PermAppRead, PermTenantRead, PermMemberRead, PermGroupRead, PermRoleRead, PermPolicyRead, PermResourceRead,
	PermInviteRead, PermServiceAccountRead}

// Built-in role slugs created in every tenant.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

var permRE = regexp.MustCompile(`^(\*|[a-z][a-z0-9_]{0,31}):(\*|[a-z][a-z0-9_]{0,31})$`)

// ValidPermission reports whether p is "<type>:<action>" (either side may be "*").
func ValidPermission(p string) bool { return permRE.MatchString(p) }

// Grants reports whether a granted permission covers action ("app:*" covers "app:access", "*:*" covers everything).
func Grants(granted, action string) bool {
	if granted == action || granted == "*:*" {
		return true
	}
	gt, ga, ok1 := strings.Cut(granted, ":")
	at, _, ok2 := strings.Cut(action, ":")
	return ok1 && ok2 && ga == "*" && gt == at
}
