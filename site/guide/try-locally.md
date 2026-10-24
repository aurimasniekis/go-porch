# Try it locally

The demo stack runs Porch with everything it needs on your machine: Caddy with its own local CA, a **fake Google**, a
demo OpenID Connect app, and `whoami` behind forward-auth. Nothing talks to the internet.

::: danger Demo only
The fake Google signs in anyone who clicks a name. Never expose the demo stack.
:::

You need Docker with Compose v2.24 or newer, `python3` and `curl`.

```sh
git clone https://github.com/aurimasniekis/go-porch.git && cd go-porch
deploy/demo/up.sh        # builds images, creates the key file, sets Porch up through the API, prints URLs
```

`up.sh` creates the owner account, the fake Google provider, tenant **Smith family** (`smith`) with a Workspace rule
for `smith.example`, the demo app and the `whoami` forward-auth app. It prints the owner's backup-login handle,
password and answers (also saved in `deploy/demo/.state/owner.txt`).

| URL | What it is |
| --- | --- |
| `https://auth.localhost:28443` | Porch: sign-in, launcher, admin UI, API, forward-auth outpost |
| `https://google.localhost:28443` | the fake Google: Ada and Bob Smith (`smith.example`), Carol (consumer account) |
| `https://demo.localhost:28443` | the demo OIDC app: shows the verified ID token and access token |
| `https://whoami.localhost:28443` | `traefik/whoami` behind Porch forward-auth: shows the identity headers it receives |

Caddy uses its own CA, so the browser warns once per host. Trust `deploy/demo/.state/ca/root.crt` or click through.

## Things to try

1. Open `https://auth.localhost:28443`, choose **Continue with Google** and pick **Ada Smith**. Ada is enrolled
   automatically, because her Google token carries `hd=smith.example`. Pick **Carol** instead and Porch refuses her:
   a consumer account is not enrolled and no invite exists.
2. From Ada's launcher, open **Demo app** (OpenID Connect) and **whoami (forward-auth)**. whoami shows the
   `X-Porch-*` headers Caddy passed on, and that Porch's own cookie never reached it.
3. Sign in with the owner's backup login (printed by `up.sh`). In **Admin**, pick the **Smith family** tenant, add a
   group, give it a role with a condition (**Policies**, **Assignments**), and open **Access explorer** to see why Ada
   is allowed or denied.
4. Enter a wrong backup password once: the backup login locks for 6 hours, but Google sign-in still works
   ([Backup login & recovery](../operators/recovery)).

```sh
deploy/demo/down.sh --keep   # stop; up.sh resumes the same installation
deploy/demo/down.sh          # remove everything, including the data and the key file
```

`deploy/demo/up.sh --manual` stops at the setup token so you can do the first-time setup in the browser yourself.
