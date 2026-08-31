# dev-idp

A minimal OpenID Connect (OIDC) mock provider for local development and automated testing.
Supports the authorization code flow (with optional PKCE), refresh tokens, client credentials, and sign out.

> [!NOTE]
> This is a _mock_ provider, and it does not implement any actual security.
> dev-idp should never be used to protect anything.

## Install

### Binary (shell)

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Nerven/dev-idp/releases/latest/download/dev-idp-installer.sh | sh
```

### Binary (PowerShell)

```powershell
# powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/Nerven/dev-idp/releases/latest/download/dev-idp-installer.ps1 | iex"
```

### Cargo

```sh
cargo install dev-idp --locked
```

### Container image

```sh
docker run --rm -p 8383:8383 -v "$PWD:/config" ghcr.io/nerven/dev-idp
```

## Usage

1. Create a [dev-idp.toml](dev-idp.toml) configuration file.

2. Run dev-idp with your config:

   ```sh
   dev-idp dev-idp.toml
   # or via docker
   docker run --rm -p 8383:8383 -v "${PWD}/dev-idp.toml:/config/dev-idp.toml" ghcr.io/nerven/dev-idp
   ```

3. Point your application at the discovery document:  
   `http://localhost:8383/.well-known/openid-configuration`

### Usage notes

- **Auto-selecting user**  
  Put a configured username in the `login_hint` parameter to skip the user picker.
- **Testing error handling**  
  Pass an error code prefix with `!` in the `login_hint` parameter (e.g. `login_hint=!access_denied`).
- **Force user picker**  
  Pass `prompt=login` to `/authorize` to force the picker despite a session,
  or set `[session] ttl_secs = 0` to disable sessions and prompt on every authorization.
- **No claim filtering**  
  All claims configured on a user will be used regardless of the requested scopes.
  Real IdPs are often stricter (e.g. releasing `email` only when the `email` scope is requested).
- **Auto generating signing key**  
  On first run a signing key is generated and written back into the config file, so it must be writable once.
  You can pre-generate the key with `dev-idp init dev-idp.toml`.

## Protocol support

Authorization code flow (`response_type=code` only, optional PKCE with `S256`, `response_mode` `query` or `form_post`),
refresh tokens, client credentials, RP-initiated logout, discovery, JWKS, userinfo,
`login_hint`, `prompt=login` and `prompt=none`,
and client authentication via `client_secret_basic`, `client_secret_post`, or `none` (public clients).

## AI/LLM usage disclosure

The development of this project has been heavily assisted by AI/LLM tools.

## Contributing

Contributions are welcome, but please create an issue first to allow us to align on a path forward.
AI/LLM assistance is allowed, but only in the hands of a person who takes responsibility for the value it provides.

### Tooling

```sh
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo mutants
```

## Demo app

```sh
cargo run -- demo/dev-idp.toml            # the IdP on :8383
cd demo && pnpm install && node serve.mjs # the app on :3000
```

### Playwright tests of demo app

```sh
cd demo
pnpm install
pnpm prep
pnpm test
```

## License

dev-idp is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE) for the full text.

Note that section 13 applies here: if you run a modified version as a network
service, you must offer its source to the users interacting with it.
