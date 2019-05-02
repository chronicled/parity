FROM alpine:edge

# show backtraces
ENV RUST_BACKTRACE 1

RUN apk add --no-cache \
  libstdc++ \
  eudev-libs \
  libgcc

RUN addgroup -g 1000 parity \
  && adduser -u 1000 -G parity -s /bin/sh -D parity

USER parity

EXPOSE 8080 8545 8180

WORKDIR /home/parity

RUN mkdir -p /home/parity/.local/share/io.parity.ethereum/
COPY --chown=parity:parity ./target/x86_64-unknown-linux-musl/release/parity ./

ENTRYPOINT ["./parity"]
