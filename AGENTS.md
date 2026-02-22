# Description

CLI tool to extract cookies from a service that uses Keycloak to authenticate requests and creates login sessions.
This tools supports the 3-legged OAuth flow necessary to obtain a session and subsequently dump cookies.

## Dev Instructions

* Always `cargo fmt`, `cargo check`, `cargo clippy` the code after changes
* Don't change edition in `Cargo.toml`
* Ask before introducing third-party dependencies
* Commits should always include you as the author (not the configured git user) and a git-karma styled message
* Don't `.clone()` unnecessarily, often restructuring the code avoids having to use `.clone()` on a value


