package mgmtapi

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/identity"
)

// User is the API representation of a user.
type User struct {
	ID            string     `json:"id"`
	PublicID      string     `json:"public_id" doc:"Stable OIDC subject (sub) of this user."`
	DisplayName   string     `json:"display_name"`
	PrimaryEmail  string     `json:"primary_email,omitempty"`
	Status        string     `json:"status" enum:"active,disabled"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	Version       int64      `json:"version"`
	ManagedBy     string     `json:"managed_by"`
	LastChangedBy string     `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	// BackupLogin is set on single-user reads only.
	BackupLogin *BackupLoginStatus `json:"backup_login,omitempty"`
}

// BackupLoginStatus describes a user's backup login (never the credential itself).
type BackupLoginStatus struct {
	Enrolled    bool       `json:"enrolled"`
	Failures    int64      `json:"failures"`
	LockedUntil *time.Time `json:"locked_until,omitempty" doc:"Set while the backup login is locked out."`
}

func userDTO(u identity.User) User {
	return User{ID: u.ID, PublicID: u.PublicID, DisplayName: u.DisplayName, PrimaryEmail: u.PrimaryEmail, Status: u.Status,
		LastLoginAt: u.LastLoginAt, Version: u.Version, ManagedBy: u.ManagedBy, LastChangedBy: u.LastChangedBy, CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt}
}

type userOutput struct {
	ETag string `header:"ETag"`
	Body User
}

// UserList is one page of users.
type UserList struct {
	Items      []User `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type UserRef struct {
	User string `path:"user" maxLength:"64" doc:"User ID."`
}

// CreateUserRequest is the request body of the operation.
type CreateUserRequest struct {
	DisplayName  string `json:"display_name" minLength:"1" maxLength:"200"`
	PrimaryEmail string `json:"primary_email,omitempty" maxLength:"254" doc:"Attribute only; never used to link login identities."`
}

// UpdateUserRequest is the request body of the operation.
type UpdateUserRequest struct {
	DisplayName  *string `json:"display_name,omitempty" minLength:"1" maxLength:"200"`
	PrimaryEmail *string `json:"primary_email,omitempty" maxLength:"254"`
	Status       *string `json:"status,omitempty" enum:"active,disabled"`
}

func registerUsers(api huma.API, d *Deps) {
	tags := []string{"users"}
	type listInput struct {
		Pagination
		Email  string `query:"email" maxLength:"254" doc:"Exact primary email."`
		Status string `query:"status" enum:"active,disabled," required:"false"`
		Query  string `query:"q" maxLength:"100" doc:"Case-insensitive substring of the name or primary email."`
	}
	huma.Register(api, huma.Operation{OperationID: "list-users", Method: http.MethodGet, Path: "/users", Summary: "List users",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *listInput) (*struct{ Body UserList }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			page, err := in.Page()
			if err != nil {
				return nil, err
			}
			us, next, err := d.Users.List(ctx, page, identity.ListFilter{Email: in.Email, Status: in.Status, Query: in.Query})
			if err != nil {
				return nil, d.fail("list-users", err)
			}
			out := UserList{Items: make([]User, 0, len(us)), NextCursor: next}
			for _, u := range us {
				out.Items = append(out.Items, userDTO(u))
			}
			return &struct{ Body UserList }{Body: out}, nil
		})

	type createInput struct {
		ManagedBy
		Body CreateUserRequest
	}
	huma.Register(api, huma.Operation{OperationID: "create-user", Method: http.MethodPost, Path: "/users", DefaultStatus: http.StatusCreated,
		Summary: "Create a user", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *createInput) (*userOutput, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			u, err := d.Users.Create(ctx, change(ctx, in.ManagedBy.ManagedBy), identity.CreateParams{DisplayName: in.Body.DisplayName,
				PrimaryEmail: in.Body.PrimaryEmail, EmailSource: "manual"})
			if err != nil {
				return nil, d.fail("create-user", err)
			}
			return &userOutput{ETag: etag(u.Version), Body: userDTO(u)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "get-user", Method: http.MethodGet, Path: "/users/{user}", Summary: "Get a user",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *UserRef) (*userOutput, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			u, err := d.Users.Get(ctx, in.User)
			if err != nil {
				return nil, d.fail("get-user", err)
			}
			out := userDTO(u)
			bl := &BackupLoginStatus{}
			if _, err := d.Store.R().GetBackupCredential(ctx, u.ID); err == nil {
				bl.Enrolled = true
			}
			if lo, err := d.Store.R().GetBackupLockout(ctx, u.ID); err == nil {
				bl.Failures = lo.Failures
				if until := time.UnixMicro(lo.LockedUntil); lo.LockedUntil > 0 && until.After(d.now()) {
					until = until.UTC()
					bl.LockedUntil = &until
				}
			}
			out.BackupLogin = bl
			return &userOutput{ETag: etag(u.Version), Body: out}, nil
		})

	type updateInput struct {
		UserRef
		ManagedBy
		IfMatch
		Body UpdateUserRequest
	}
	huma.Register(api, huma.Operation{OperationID: "update-user", Method: http.MethodPatch, Path: "/users/{user}", Summary: "Update a user",
		Description: "Disabling a user ends all of their sessions immediately.", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *updateInput) (*userOutput, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			if in.Body.Status != nil && *in.Body.Status != "active" {
				if err := d.mayRemoveOperator(ctx, in.User); err != nil {
					return nil, err
				}
			}
			u, err := d.Users.Update(ctx, change(ctx, in.ManagedBy.ManagedBy), in.User, identity.UpdateParams{DisplayName: in.Body.DisplayName,
				PrimaryEmail: in.Body.PrimaryEmail, Status: in.Body.Status, IfVersion: v})
			if err != nil {
				return nil, d.fail("update-user", err)
			}
			return &userOutput{ETag: etag(u.Version), Body: userDTO(u)}, nil
		})

	type deleteInput struct {
		UserRef
		ManagedBy
		IfMatch
	}
	huma.Register(api, huma.Operation{OperationID: "delete-user", Method: http.MethodDelete, Path: "/users/{user}", DefaultStatus: http.StatusNoContent,
		Summary: "Delete a user", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *deleteInput) (*struct{}, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			if err := d.mayRemoveOperator(ctx, in.User); err != nil {
				return nil, err
			}
			if err := d.Users.Delete(ctx, change(ctx, in.ManagedBy.ManagedBy), in.User, v); err != nil {
				return nil, d.fail("delete-user", err)
			}
			return &struct{}{}, nil
		})
}

// mayRemoveOperator guards disabling or deleting a user with installation roles (review M6): automation tokens never
// may, only owners may act on owners, and the last active owner stays.
func (d *Deps) mayRemoveOperator(ctx context.Context, userID string) error {
	roles, err := d.Store.R().ListOperatorRoles(ctx, userID)
	if err != nil {
		return d.fail("operator-guard", err)
	}
	if len(roles) == 0 {
		return nil
	}
	p := Principal(ctx)
	if p.Token != nil {
		return problem(http.StatusForbidden, apperr.CodeForbidden, "users with installation roles can only be disabled or deleted interactively", nil)
	}
	if !slices.Contains(roles, identity.RoleOwner) {
		return nil
	}
	if !p.IsOperator(identity.RoleOwner) {
		return problem(http.StatusForbidden, apperr.CodeForbidden, "only owners can disable or delete an owner", nil)
	}
	n, err := d.Store.R().CountActiveOwnersExcept(ctx, userID)
	if err != nil {
		return d.fail("operator-guard", err)
	}
	if n == 0 {
		return problem(http.StatusConflict, apperr.CodeConflict, "the installation must keep at least one active owner", nil)
	}
	return nil
}
