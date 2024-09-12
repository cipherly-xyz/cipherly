FROM rust:1.81 as build

WORKDIR /secretshare

# install trunk
RUN cargo install --locked trunk

RUN rustup target add wasm32-unknown-unknown

COPY . .

WORKDIR /secretshare/frontend

RUN trunk build --release

FROM caddy:alpine

COPY --from=build /secretshare/frontend/dist .

CMD ["caddy", "file-server", "root", "/dist"]
