// Package fakeidp is an in-process OpenID Connect provider that behaves like Google for Porch's tests and demo stack:
// discovery, JWKS, authorization code + PKCE, ID tokens with Google-style claims (hd, email_verified), prompt=none
// (login_required when the user has no session or was removed), prompt=login / max_age (fresh auth_time) and an
// interactive user picker.
//
// Adapted from HallPass internal/oidc/oidctest (Apache-2.0). It is a test fixture: it is never compiled into the porch
// server binary and must never be exposed to real users.
package fakeidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is an account at the fake provider.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	// HD is the Google Workspace hosted domain ("" for consumer accounts).
	HD string
	// Extra claims merged into the ID token.
	Extra map[string]any
	// Disabled users get login_required on prompt=none and are refused interactively (removed from Workspace).
	Disabled bool
}

// Client is a registered relying party.
type Client struct {
	ID, Secret string
	// RedirectURIs are matched exactly.
	RedirectURIs []string
}

// IdP is the fake provider. Configure fields under Set; it is safe for concurrent use.
type IdP struct {
	mu       sync.Mutex
	issuer   string
	key      *rsa.PrivateKey
	kid      string
	users    map[string]*User
	clients  map[string]Client
	codes    map[string]grant
	sessions map[string]string // browser session cookie → subject (interactive mode)

	// Current is the subject logged in automatically on non-interactive authorize (tests). "" = show the picker.
	Current string
	// Mutate edits ID token claims before signing (attack tests: wrong aud, missing nonce, forged hd, …).
	Mutate func(claims map[string]any)
	// Now is the provider clock.
	Now func() time.Time
	// LastAuthorize is the query of the most recent authorization request.
	LastAuthorize url.Values
}

type grant struct {
	client, challenge, nonce, redirect string
	user                               User
	authTime                           time.Time
}

// New returns a provider whose issuer is issuer (the URL it will be served at).
func New(issuer string) (*IdP, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &IdP{issuer: issuer, key: k, kid: "fake-" + randomString()[:8], users: map[string]*User{}, clients: map[string]Client{},
		codes: map[string]grant{}, sessions: map[string]string{}, Now: time.Now}, nil
}

// Issuer returns the issuer URL.
func (i *IdP) Issuer() string { return i.issuer }

// SetIssuer changes the issuer (tests that learn the URL only after starting a server).
func (i *IdP) SetIssuer(iss string) {
	i.mu.Lock()
	i.issuer = iss
	i.mu.Unlock()
}

// AddUser registers or replaces a user.
func (i *IdP) AddUser(u User) {
	i.mu.Lock()
	defer i.mu.Unlock()
	c := u
	i.users[u.Subject] = &c
}

// UpdateUser edits a user in place.
func (i *IdP) UpdateUser(sub string, fn func(*User)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if u, ok := i.users[sub]; ok {
		fn(u)
	}
}

// AddClient registers a client.
func (i *IdP) AddClient(c Client) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.clients[c.ID] = c
}

// Set runs fn with the provider locked.
func (i *IdP) Set(fn func(*IdP)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	fn(i)
}

// Handler serves the provider endpoints.
func (i *IdP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", i.discovery)
	mux.HandleFunc("GET /jwks", i.jwks)
	mux.HandleFunc("GET /authorize", i.authorize)
	mux.HandleFunc("POST /authorize", i.pick)
	mux.HandleFunc("POST /token", i.token)
	return mux
}

func (i *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	iss := i.issuer
	i.mu.Unlock()
	writeJSON(w, map[string]any{"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
		"jwks_uri": iss + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
		"scopes_supported": []string{"openid", "email", "profile"}})
}

func (i *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &i.key.PublicKey, KeyID: i.kid, Algorithm: "RS256", Use: "sig"}}})
}

const sessionCookie = "fakeidp_session"

func (i *IdP) validateAuthorize(q url.Values) (Client, string) {
	c, ok := i.clients[q.Get("client_id")]
	switch {
	case !ok:
		return c, "unknown client_id"
	case !slices.Contains(c.RedirectURIs, q.Get("redirect_uri")):
		return c, "redirect_uri not registered"
	case q.Get("response_type") != "code":
		return c, "response_type must be code"
	case q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		return c, "PKCE S256 required"
	}
	return c, ""
}

// authorize: prompt=none uses the browser session (or Current); otherwise Current logs in, or the picker is shown.
func (i *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.LastAuthorize = q
	if _, msg := i.validateAuthorize(q); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	sub := i.Current
	if sub == "" {
		if c, err := r.Cookie(sessionCookie); err == nil {
			sub = i.sessions[c.Value]
		}
	}
	if q.Get("prompt") == "none" {
		u, ok := i.users[sub]
		if !ok || u.Disabled {
			i.redirectError(w, r, q, "login_required")
			return
		}
		i.issueCode(w, r, q, *u, false)
		return
	}
	if i.Current != "" {
		u, ok := i.users[i.Current]
		if !ok || u.Disabled {
			i.redirectError(w, r, q, "access_denied")
			return
		}
		i.issueCode(w, r, q, *u, true)
		return
	}
	i.renderPicker(w, q)
}

var pickerTmpl = template.Must(template.New("p").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Fake Google sign-in</title>
<style>body{font-family:system-ui;max-width:32rem;margin:3rem auto}button{display:block;width:100%;margin:.5rem 0;padding:.75rem;text-align:left}</style>
</head><body><h1>Fake Google</h1><p>Test identity provider — not a real Google login.</p>
<form method="post">{{range $k, $v := .Query}}<input type="hidden" name="{{$k}}" value="{{index $v 0}}">{{end}}
{{range .Users}}<button name="subject" value="{{.Subject}}"{{if .Disabled}} disabled{{end}}>{{.Name}} &lt;{{.Email}}&gt;{{if .HD}} — {{.HD}}{{end}}{{if .Disabled}} (removed){{end}}</button>{{end}}
</form></body></html>`))

func (i *IdP) renderPicker(w http.ResponseWriter, q url.Values) {
	users := make([]User, 0, len(i.users))
	for _, u := range i.users {
		users = append(users, *u)
	}
	slices.SortFunc(users, func(a, b User) int {
		if a.Email < b.Email {
			return -1
		}
		return 1
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pickerTmpl.Execute(w, map[string]any{"Query": q, "Users": users})
}

func (i *IdP) pick(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	q := url.Values{}
	for k, v := range r.PostForm {
		if k != "subject" {
			q[k] = v
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, msg := i.validateAuthorize(q); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	u, ok := i.users[r.PostForm.Get("subject")]
	if !ok || u.Disabled {
		i.redirectError(w, r, q, "access_denied")
		return
	}
	sid := randomString()
	i.sessions[sid] = u.Subject
	// The fake provider runs over plain http in tests and the demo; its session cookie protects nothing real.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}) //nolint:gosec // test fixture
	i.issueCode(w, r, q, *u, true)
}

func (i *IdP) issueCode(w http.ResponseWriter, r *http.Request, q url.Values, u User, fresh bool) {
	code := randomString()
	authTime := i.Now()
	if !fresh {
		authTime = authTime.Add(-30 * time.Minute) // silent re-auth keeps the original login time
	}
	i.codes[code] = grant{client: q.Get("client_id"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"),
		user: u, authTime: authTime}
	target, _ := url.Parse(q.Get("redirect_uri"))
	rq := target.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	rq.Set("iss", i.issuer)
	target.RawQuery = rq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound) //nolint:gosec // redirect_uri was matched against the registration
}

func (i *IdP) redirectError(w http.ResponseWriter, r *http.Request, q url.Values, code string) {
	target, _ := url.Parse(q.Get("redirect_uri"))
	rq := target.Query()
	rq.Set("error", code)
	rq.Set("state", q.Get("state"))
	target.RawQuery = rq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound) //nolint:gosec // redirect_uri was matched against the registration
}

func (i *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, known := i.clients[id]
	if !known || c.Secret != secret {
		tokenError(w, "invalid_client")
		return
	}
	g, found := i.codes[r.PostForm.Get("code")]
	delete(i.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || g.client != id || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != g.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		tokenError(w, "invalid_grant")
		return
	}
	now := i.Now()
	claims := map[string]any{"iss": i.issuer, "sub": g.user.Subject, "aud": id, "azp": id, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"auth_time": g.authTime.Unix(), "email": g.user.Email, "email_verified": g.user.EmailVerified, "name": g.user.Name}
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	if g.user.HD != "" {
		claims["hd"] = g.user.HD
	}
	maps.Copy(claims, g.user.Extra)
	if i.Mutate != nil {
		i.Mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: i.key, KeyID: i.kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	obj, err := s.Sign(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idt, _ := obj.CompactSerialize()
	writeJSON(w, map[string]any{"access_token": "fake-at-" + randomString(), "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
