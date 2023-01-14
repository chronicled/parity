FROM rust:1.44 AS builder
# show backtraces
ENV RUST_BACKTRACE 1

RUN apt update -y && \
	apt upgrade -y && \
	apt install -y perl yasm libudev-dev linux-headers-amd64 gcc g++ pkg-config file make cmake libssl1.1

WORKDIR /parity
COPY . /parity
RUN cargo build --release
RUN strip target/release/parity

FROM debian:buster

# show backtraces
ENV RUST_BACKTRACE 1

RUN addgroup --gid 1000 parity && \
	adduser --uid 1000 --ingroup parity --shell /bin/sh parity
RUN apt-get update -y && \
	apt-get install -y libssl1.1

USER parity

EXPOSE 8080 8545 8180

WORKDIR /home/parity

RUN mkdir -p /home/parity/keys/prv/
RUN mkdir -p /home/parity/node0/network/
RUN mkdir -p /home/parity/node0/keys/prv
RUN mkdir -p /home/parity/.local/share/io.parity.ethereum/
RUN mkdir -p /home/parity/src
RUN chown -R parity:parity /home/parity

COPY . /home/parity/src
COPY --from=builder /parity/target/release/parity ./

ENTRYPOINT ["./parity"]
