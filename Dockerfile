FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p transfer-server

FROM debian:stable-slim
RUN useradd --system --create-home transfer \
    && install -d -o transfer -g transfer /home/transfer/data
COPY --from=build /src/target/release/transfer-server /usr/local/bin/transfer-server
USER transfer
ENV TRANSFER_DATA_DIR=/home/transfer/data
EXPOSE 7443 7444
CMD ["transfer-server", "all"]
