FROM alpine:latest

WORKDIR /app

COPY ./target/release/artico ./artico

COPY ./migrations ./migrations

CMD ["./artico"]
