# kc-cookie-dump

CLI tool to authenticate against a service protected by **Keycloak** and dump selected cookies to disk.

The tool:
1. Calls the service URL and follows redirects to Keycloak.
2. Parses the Keycloak login form (action URL + username/password fields).
3. Prompts for username and password (password is not echoed).
4. Submits the login form, follows redirects back to the service.
5. Collects `Set-Cookie` headers and writes the **last** `Set-Cookie` value per requested cookie name.

## Usage

```bash
kc-cookie-dump \
  --url https://service.example.com/ \
  --cookie SESSION \
  --cookie XSRF-TOKEN \
  --out-dir ./cookies
```

### Output

For each `--cookie NAME`, a file is written:

- `./cookies/NAME.set-cookie`

The file content is the **raw `Set-Cookie` header value**.

## Options

- `--url <URL>`: Service URL to start the login flow.
- `--cookie <NAME>`: Cookie name to dump (repeatable, required).
- `--out-dir <DIR>`: Output directory (default: current directory).
- `--max-redirects <N>`: Safety limit for redirect following (default: 30).

## TLS note

This tool accepts invalid/self-signed TLS certificates (intended for internal deployments). Use with care.
