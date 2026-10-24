package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

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
		Email  string `query:"email" maxLength:"254"`
		Status string `query:"status" enum:"active,disabled," required:"false"`
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
			us, next, err := d.Users.List(ctx, page, identity.ListFilter{Email: in.Email, Status: in.Status})
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
			return &userOutput{ETag: etag(u.Version), Body: userDTO(u)}, nil
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
			if err := d.Users.Delete(ctx, change(ctx, in.ManagedBy.ManagedBy), in.User, v); err != nil {
				return nil, d.fail("delete-user", err)
			}
			return &struct{}{}, nil
		})
}
