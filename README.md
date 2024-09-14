# Cipherly

Cipherly was built to enable people to securely share secrets.
The main goals are post quantum security and usability, while minimizing the chance for human error by eliminating the need to exchange sensitive information (shared keys) or store private keys.

## Development

### Backend

The SQLite database is configured using the `DATABASE_URL` environment variable.
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
Cipherly uses [Trunk](https://trunkrs.dev/) to buld and bundle the frontend.
In the `frontend/` directory, run

```sh
trunk serve
```

The frontend will be available at `http://localhost:8080`.
Trunk is configured to proxy requests backend requests to `http://localhost:3000/api` (see `Trunk.toml`)

Use the `debug=1` query parameter to display frontend state information in the UI.

## Deployment

There are docker images for the backend and the frontend.
Images are built by GitHub Actions and pushed to GitHub Container Registry on every version tag.

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

## Contributing

This project uses [conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## Attributions

- Icons: https://heroicons.com/, MIT License
- CSS: https://picocss.com/, MIT License