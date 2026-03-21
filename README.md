# kc-cookie-dump

CLI tool to authenticate against a service protected by **Keycloak** and dump selected cookies to disk.

The tool:
1. Calls the service URL and follows redirects to Keycloak.
2. Parses the Keycloak login form (action URL + username/password fields).
3. Prompts for username and password (password is not echoed).
4. Submits the login form, follows redirects back to the service.
5. Collects `Set-Cookie` headers and writes the **last** `Set-Cookie` value per requested cookie name.
6. Always writes a combined Netscape/curl cookie jar containing every requested cookie.

## Usage

```bash
kc-cookie-dump \
  --url https://service.example.com/ \
  --cookie SESSION \
  --cookie XSRF-TOKEN
```

### Output

By default the tool writes a single cookie jar:

- `./cookies.jar`

The file content uses the Netscape cookie jar format understood by tools such as `curl`.

Use `--cookie-jar` to choose a different jar path:

```bash
kc-cookie-dump \
  --url https://service.example.com/ \
  --cookie SESSION \
  --cookie XSRF-TOKEN \
  --cookie-jar ./artifacts/service.cookies
```

Use `--dump-cookies` to additionally write one raw `Set-Cookie` file per requested cookie:

```bash
kc-cookie-dump \
  --url https://service.example.com/ \
  --cookie SESSION \
  --cookie XSRF-TOKEN \
  --dump-cookies \
  --out-dir ./cookies
```

With `--dump-cookies`, the tool also writes:

- `./cookies/SESSION.set-cookie`
- `./cookies/XSRF-TOKEN.set-cookie`

Each per-cookie file contains the raw `Set-Cookie` header value.

## Options

- `--url <URL>`: Service URL to start the login flow.
- `--cookie <NAME>`: Cookie name to dump (repeatable, required).
- `--cookie-jar <PATH>`: Output path for the combined cookie jar (default: `./cookies.jar`).
- `--dump-cookies`: Also write one raw `Set-Cookie` file per requested cookie.
- `--out-dir <DIR>`: Output directory for per-cookie files written by `--dump-cookies` (default: current directory).
- `--max-redirects <N>`: Safety limit for redirect following (default: 30).

## TLS note

This tool accepts invalid/self-signed TLS certificates (intended for internal deployments). Use with care.
