FROM rust:alpine AS builder
WORKDIR /home/rust/src
COPY . .
RUN cargo build --release --package p2p-relay

FROM scratch
COPY --from=builder /home/rust/src/target/release/p2p-relay .
USER 1000:1000
ENTRYPOINT ["./p2p-relay"]
