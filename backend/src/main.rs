use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_macros::debug_handler;
use sqlx::SqlitePool;

#[derive(Clone)]
struct AppState {
    db_pool: SqlitePool,
}

fn delete_expired_secrets_periodically(
    db_pool: SqlitePool,
    delete_expired_interval: std::time::Duration,
) {
    tokio::spawn({
        let db_pool = db_pool.clone();
        async move {
            loop {
                log::debug!("Cleaning expired secrets...");

                let id = sqlx::query(
                    r#"
                    delete from secrets where expiration < strftime('%s')
                "#,
                )
                .execute(&db_pool)
                .await;

                match id {
                    Ok(r) => log::info!("Cleaned {} expired secrets", r.rows_affected()),
                    Err(e) => log::error!("Failed to clean expired secrets: {:?}", e),
                }
                tokio::time::sleep(delete_expired_interval).await;
            }
        }
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()?;

    let db_url = std::env::var("DATABASE_URL")?;
    log::info!("{:?}", db_url);

    let db_pool = SqlitePool::connect(&db_url).await?;

    delete_expired_secrets_periodically(db_pool.clone(), Duration::from_secs(600));

    let state = AppState { db_pool };

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/api/accounts", post(create_account))
        .route("/api/accounts/:username", get(get_account))
        .route("/api/secrets", post(create_secret))
        .route("/api/secrets/:secret_id", get(get_secret))
        .with_state(state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

#[debug_handler]
async fn create_account(
    state: State<AppState>,
    payload: axum::Json<core::CreateAccount>,
) -> impl IntoResponse {
    let pool = &state.db_pool;

    let public_key = match core::decode_base64(&payload.public_key) {
        Ok(key) => key,
        Err(_) => {
            log::error!("Failed to base64 decode public key");
            return StatusCode::BAD_REQUEST;
        }
    };

    let id = sqlx::query(
        r#"
            INSERT INTO accounts (
                username,
                public_key
            )
            VALUES (?, ?)
            RETURNING id;
            "#,
    )
    .bind(&payload.username)
    .bind(&public_key)
    .execute(pool)
    .await;

    match id {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            log::error!("Failed to insert account: {:?}", e);

            if let Some(dberror) = e.into_database_error() {
                if let Some(code) = dberror.code() {
                    if code == "2067" {
                        return StatusCode::CONFLICT;
                    }
                }
            }
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(sqlx::FromRow, Debug)]
struct Account {
    id: i64,
    username: String,
    public_key: Vec<u8>,
}

impl From<Account> for core::Account {
    fn from(account: Account) -> Self {
        let pk = core::encode_bas64(&account.public_key);
        Self {
            id: account.id,
            username: account.username,
            public_key: pk,
        }
    }
}

#[debug_handler]
async fn get_account(
    state: State<AppState>,
    username: axum::extract::Path<String>,
) -> (StatusCode, axum::Json<Option<core::Account>>) {
    let pool = &state.db_pool;

    let account: Result<Account, sqlx::Error> = sqlx::query_as(
        r#"
            SELECT * FROM accounts WHERE username = ?;
            "#,
    )
    .bind(username.0)
    .fetch_one(pool)
    .await;

    match account {
        Ok(account) => {
            log::debug!("Got account: {:?}", account);

            let resp = core::Account::from(account);
            (StatusCode::OK, axum::Json(Some(resp)))
        }
        Err(sqlx::Error::RowNotFound) => (StatusCode::NOT_FOUND, axum::Json(None)),
        Err(e) => {
            log::error!("Failed to get account: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(None))
        }
    }
}

#[debug_handler]
async fn create_secret(
    state: State<AppState>,
    payload: axum::Json<core::CreateSecret>,
) -> (StatusCode, axum::Json<Option<core::SecretCreated>>) {
    let pool = &state.db_pool;

    let id = sqlx::query(
        r#"
            INSERT INTO secrets (
                ciphertext,
                enc_key,
                expiration,
                nonce
            )
            VALUES (?, ?, ?, ?)
            RETURNING id;
            "#,
    )
    .bind(&payload.ciphertext) // TODO: ciphertext and enc_key should be base64 encoded or not, not mixed
    .bind(&core::decode_base64(&payload.encapsulated_sym_key).unwrap())
    .bind(payload.expiration)
    .bind(&core::decode_base64(&payload.nonce).unwrap())
    .execute(pool)
    .await;

    match id {
        Ok(id) => (
            StatusCode::CREATED,
            axum::Json(Some(core::SecretCreated {
                id: id.last_insert_rowid().to_string(),
            })),
        ),
        Err(e) => {
            log::error!("Failed to insert secret: {:?}", e);

            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(None))
        }
    }
}

#[derive(sqlx::FromRow, Debug)]
struct Secret {
    id: i64,
    ciphertext: String,
    enc_key: Vec<u8>,
    nonce: Vec<u8>,
}

impl From<Secret> for core::GetSecret {
    fn from(secret: Secret) -> Self {
        Self {
            id: secret.id,
            ciphertext: secret.ciphertext,
            encapsulated_sym_key: core::encode_bas64(&secret.enc_key),
            nonce: core::encode_bas64(&secret.nonce),
        }
    }
}

#[debug_handler]
async fn get_secret(
    state: State<AppState>,
    secret_id: axum::extract::Path<String>,
) -> (StatusCode, axum::Json<Option<core::GetSecret>>) {
    let pool = &state.db_pool;

    // since expired secrets are deleted periodically, we exclude expired
    // but not yet deleted secrets in the query
    let secret: Result<Secret, sqlx::Error> = sqlx::query_as(
        r#"
            SELECT * FROM secrets WHERE
                id = ? and
                expiration > strftime('%s');
            "#,
    )
    .bind(secret_id.0)
    .fetch_one(pool)
    .await;

    match secret {
        Ok(secret) => {
            log::debug!("Got secret: {:?}", secret);

            let resp = core::GetSecret::from(secret);
            (StatusCode::OK, axum::Json(Some(resp)))
        }
        Err(sqlx::Error::RowNotFound) => (StatusCode::NOT_FOUND, axum::Json(None)),
        Err(e) => {
            log::error!("Failed to get secret: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(None))
        }
    }
}
