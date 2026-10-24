package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	sessionTTL      = 8 * time.Hour
	pendingLoginTTL = 10 * time.Minute
	maxSessions     = 10000
)

var errTooManySessions = errors.New("too many active sessions")

// pendingLogin is what /login remembers for /callback. It lives only on the server.
type pendingLogin struct {
	State, Nonce, Verifier string
	Expires                time.Time
}

// signedIn is everything the demo got from Porch. Tokens never leave the server except into the rendered page.
type signedIn struct {
	Token       *oauth2.Token
	RawIDToken  string
	Subject     string
	IDClaims    map[string]any
	IDClaimsRaw string
	Access      accessTokenView
	UserInfo    string
	UserInfoErr string
	SignedInAt  time.Time
	RefreshedAt time.Time
}

// session is a server-side session. Values are copied in and out of the store; pointers inside are never mutated
// after being stored.
type session struct {
	ID      string
	CSRF    string
	Expires time.Time
	Pending *pendingLogin
	User    *signedIn
	// Flash is a one-shot notice shown on the next page view.
	Flash      string
	FlashError bool
}

// sessionStore is an in-memory session map keyed by a random cookie value.
type sessionStore struct {
	mu   sync.Mutex
	m    map[string]session
	now  func() time.Time
	name string
	// secure sets the Secure attribute (and the __Host- prefix) on the cookie.
	secure bool
}

func newSessionStore(secure bool) *sessionStore {
	name := "porch_demo"
	if secure {
		name = "__Host-porch_demo"
	}
	return &sessionStore{m: map[string]session{}, now: time.Now, name: name, secure: secure}
}

// create stores a fresh session (new ID and CSRF token) and sets its cookie.
func (s *sessionStore) create(w http.ResponseWriter, base session) (session, error) {
	base.ID = randomToken()
	base.CSRF = randomToken()
	base.Expires = s.now().Add(sessionTTL)
	s.mu.Lock()
	now := s.now()
	for id, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, id)
		}
	}
	if len(s.m) >= maxSessions {
		s.mu.Unlock()
		return session{}, errTooManySessions
	}
	s.m[base.ID] = base
	s.mu.Unlock()
	s.setCookie(w, base.ID, int(sessionTTL.Seconds()))
	return base, nil
}

// get returns the request's live session.
func (s *sessionStore) get(r *http.Request) (session, bool) {
	c, err := r.Cookie(s.name)
	if err != nil || c.Value == "" {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[c.Value]
	if !ok {
		return session{}, false
	}
	if s.now().After(v.Expires) {
		delete(s.m, c.Value)
		return session{}, false
	}
	return v, true
}

// put replaces a session if it still exists (it may have been destroyed by a concurrent logout).
func (s *sessionStore) put(v session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[v.ID]; ok {
		s.m[v.ID] = v
	}
}

// drop deletes the session server-side (the caller replaces the cookie with create).
func (s *sessionStore) drop(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// destroy deletes the session and expires its cookie.
func (s *sessionStore) destroy(w http.ResponseWriter, id string) {
	s.drop(id)
	s.setCookie(w, "", -1)
}

func (s *sessionStore) setCookie(w http.ResponseWriter, value string, maxAge int) {
	// Secure is on unless the operator set DEMO_INSECURE_COOKIES for plain-http localhost.
	http.SetCookie(w, &http.Cookie{Name: s.name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, //nolint:gosec // Secure is configurable, see above
		Secure: s.secure, SameSite: http.SameSiteLaxMode})
}

// validCSRF compares the submitted form token with the session's in constant time.
func validCSRF(sess session, submitted string) bool {
	return sess.CSRF != "" && subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(submitted)) == 1
}

// randomToken returns 256 bits of crypto/rand as base64url.
func randomToken() string {
	b := make([]byte, 32)
	// crypto/rand.Read never returns an error on supported platforms (it crashes the program instead).
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
