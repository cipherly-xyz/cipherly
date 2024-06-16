use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_macros::debug_handler;
use sqlx::SqlitePool;

use log;

#[derive(Clone)]
struct AppState {
    db_pool: SqlitePool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()?;

    let db_url = std::env::var("DATABASE_URL")?;
    log::info!("{:?}", db_url);

    let db_pool = SqlitePool::connect(&db_url).await?;

    let state = AppState { db_pool };

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/api/accounts", post(create_account))
        .route("/api/accounts/:username", get(get_account))
        .route("/api/secrets", post(create_secret))
        
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

    let public_key = match core::decode_public_key(&payload.public_key) {
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
        
        let pk = core::encode_public_key(&account.public_key);
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
) -> (StatusCode, axum::Json<core::Account>) {
    let pool = &state.db_pool;

    let account: Result<Account, sqlx::Error> = sqlx::query_as(
        r#"
            SELECT * FROM accounts WHERE username = ?;
            "#
    )
    .bind(username.0)
    .fetch_one(pool)
    .await;
    
    if let Ok(account) = account {
        log::info!("Got account: {:?}", account);
        
        let resp = core::Account::from(account);
        return (StatusCode::OK, axum::Json(resp))
    }
    
    todo!()

}

#[debug_handler]
async fn create_secret(
    state: State<AppState>,
    payload: axum::Json<core::CreateSecret>,
) -> (StatusCode, axum::Json<Option<core::SecretCreated>>)  {
    let pool = &state.db_pool;

    let id = sqlx::query(
        r#"
            INSERT INTO secrets (
                ciphertext,
                enc_key
            )
            VALUES (?, ?)
            RETURNING id;
            "#,
    )
    .bind(&payload.ciphertext)
    .bind(&payload.enc_key)
    .execute(pool)
    .await;

    match id {
        Ok(id) => (StatusCode::CREATED, axum::Json(Some(core::SecretCreated{id:id.last_insert_rowid().to_string(),}))),
        Err(e) => {
            log::error!("Failed to insert secret: {:?}", e);

            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(None))
        }
    }
}