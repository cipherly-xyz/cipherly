# Cipherly

Cipherly was built to enable people to securely share secrets.
The main goals are post quantum security and usability, while minimizing the chance for human error by eliminating the need to exchange sensitive information (shared keys) or store private keys.

This readme contains information about development and deployment.

See the [documentation](https://github.com/cipherly-xyz/cipherly/blob/main/docs/README.adoc) in the `docs/` directory for more information about the cryptography and impementation.

## Features

- Post quantum security
- Easy sharing via secure links that can safely be shared publicly
- No need to exchange keys or passwords
- Automatic deletion of secrets
- Recipient authentication using digital fingerprints
- No registation needed to send a secret
- Open source with attested build provenance


## Development

the project is split in three parts: the `frontend`, the `backend` and a `core` crate.
The `core` crate defines data models exchanged between the frontend and the backend (request and response bodies).

### Backend

The backend is a Rust application using the [Axum](https://github.com/tokio-rs/axum) web application framework and [SQLx](https://github.com/launchbadge/sqlx).

The SQLite database is configured with the `DATABASE_URL` environment variable.
You can create a `config.toml` in the `backend/.cargo` directory to tell cargo to set the environment variable when running the server:

```toml
[env]
DATABASE_URL="sqlite:./db.sqlite"
```

You will need the `sqlx` CLI tool to create the database and run migrations ([Installation](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#install)).

To create the database, run the following command in the `backend/` directory:

```sh
DATABASE_URL="sqlite:./db.sqlite" sqlx database setup
```

To start the server, run the following command in the `backend/` directory:

```sh
cargo run
```

### Frontend

The frontend is developed using Rust and [Alpine.js](https://alpinejs.dev).
the Rust part contains the cryptography and the communication with the backend and i scompiled to WebAssembly.
Alpine.js is used to render the application state and handle user inputs.
When the user triggers an action, Alpine.js calls the Rust/WebAssembly functions and passes the current state.
Rust returns the new state, which is then rendered by Alpine.js.

Cipherly uses [Trunk](https://trunkrs.dev/) to build and bundle the frontend.
In the `frontend/` directory, run

```sh
trunk serve
```

The frontend will be available at `http://localhost:8080`.
Trunk is configured to proxy requests backend requests to `http://localhost:3000/api` (see `Trunk.toml`).
It is recommended to build the frontend in `release` mode because argon2id is slow in debug mode, the config file contains this setting.

Use the `debug=1` query parameter to display frontend state information in the UI.

#### Compatibility Tests

To avoid the loss of user data, is important that key generation, encryption and decryption stay compatible between versions.
The same password must always generate the same keys, regardless of the KDF or Kyber implementation or Cipherly version.

To detect breaking changes, the frontend contains a some test to ensure compatibility with known values.

```sh
cargo test
```

The tests are executed on every `push` using GitHub Actions.

## Deployment

There are docker images for the backend and the frontend.
Images are built by GitHub Actions and pushed to GitHub Container Registry on every new version tag.

The frontend uses Caddy as a static site server.

The backend will automatically run the database migrations on startup using sqlx.

`deployment/` contains a compose.yml the frontend, backend and Caddy as reverse proxy.
To confgure the hostname where Caddy listens, crate the following .env file in the directory:

```sh
HOSTNAME=example.org
```

To start the deployment, run:

```sh
docker-compose up -d
```

### Continuous Deployment

When images are build and pushed to the GitHub Container Registry, a [webhook](https://github.com/adnanh/webhook) triggers a deployment on the server.

```json
[
  {
    "id": "redeploy",
    "execute-command": "</path/to/redeploy.sh>",
    "command-working-directory": "</path/to/cipherly>/deployment"
,
"trigger-rule": {
      "and": [
        {
          "match": {
            "type": "payload-hash-sha1",
            "secret": "<secret from repository settings>",
            "parameter": {
              "source": "header",
              "name": "X-Hub-Signature"
            }
          }
        },
        {
          "match": {
            "type": "value",
            "value": "completed",
            "parameter": {
              "source": "payload",
              "name": "action"
            }
          }
        },
        {
          "match": {
            "type": "value",
            "value": ".github/workflows/docker.yml",
            "parameter": {
              "source": "payload",
              "name": "workflow_run.path"
            }
          }
        }
      ]
    }
  }
]
```

`redeploy.sh` contains the following script:

```sh
#!/usr/bin/env sh
git pull &&
docker compose pull &&
docker compose down &&
docker compose up -d
```

## Contributing

This project uses [conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## Attributions

- Icons: https://heroicons.com/, MIT License
- CSS: https://picocss.com/, MIT License