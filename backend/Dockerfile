# TODO: release profile

FROM rust:1.81 as build

# install sqlx
RUN cargo install sqlx-cli --no-default-features --features sqlite

WORKDIR /secretshare
COPY . .

RUN cargo build --bin backend

FROM debian:bookworm-slim

COPY --from=build /secretshare/target/debug/backend .
COPY --from=build /secretshare/backend/migrations /migrations
COPY --from=build /secretshare/backend/init.sh .
COPY --from=build /usr/local/cargo/bin/sqlx .

RUN chmod +x /init.sh
CMD ["/init.sh"]