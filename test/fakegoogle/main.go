// Command fakegoogle runs Porch's fake Google OpenID provider for end-to-end tests and the demo stack. It is a test
// fixture: it signs in whoever clicks a name and must never face real users.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/idp/fakeidp"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9999", "listen address")
	issuer := flag.String("issuer", "http://127.0.0.1:9999", "issuer URL (as reachable by Porch and the browser)")
	clientID := flag.String("client-id", "porch", "OAuth client ID")
	secret := flag.String("client-secret", "porch-dev-secret", "OAuth client secret")
	redirects := flag.String("redirect-uris", "http://localhost:8080/login/google/callback", "comma-separated redirect URIs")
	users := flag.String("users", "", "JSON file with users [{subject,email,email_verified,name,hd,disabled}]")
	flag.Parse()

	idp, err := fakeidp.New(strings.TrimSuffix(*issuer, "/"))
	if err != nil {
		log.Fatal(err)
	}
	idp.AddClient(fakeidp.Client{ID: *clientID, Secret: *secret, RedirectURIs: strings.Split(*redirects, ",")})
	if err := loadUsers(idp, *users); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", idp.Handler())
	// Test control endpoint: toggle a user's Workspace membership (disabled) or hosted domain.
	mux.HandleFunc("POST /_control/users/{sub}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Disabled *bool   `json:"disabled"`
			HD       *string `json:"hd"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		idp.UpdateUser(r.PathValue("sub"), func(u *fakeidp.User) {
			if in.Disabled != nil {
				u.Disabled = *in.Disabled
			}
			if in.HD != nil {
				u.HD = *in.HD
			}
		})
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	fmt.Fprintf(os.Stderr, "fake Google (TEST ONLY) issuer %s on %s\n", idp.Issuer(), *listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadUsers(idp *fakeidp.IdP, path string) error {
	if path == "" {
		idp.AddUser(fakeidp.User{Subject: "ada", Email: "ada@smith.example", EmailVerified: true, Name: "Ada Smith", HD: "smith.example"})
		idp.AddUser(fakeidp.User{Subject: "bob", Email: "bob@smith.example", EmailVerified: true, Name: "Bob Smith", HD: "smith.example"})
		idp.AddUser(fakeidp.User{Subject: "carol", Email: "carol@gmail.example", EmailVerified: true, Name: "Carol (consumer)"})
		return nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		return err
	}
	var us []struct {
		Subject       string `json:"subject"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		HD            string `json:"hd"`
		Disabled      bool   `json:"disabled"`
	}
	if err := json.Unmarshal(b, &us); err != nil {
		return err
	}
	for _, u := range us {
		idp.AddUser(fakeidp.User{Subject: u.Subject, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.Name, HD: u.HD, Disabled: u.Disabled})
	}
	return nil
}
