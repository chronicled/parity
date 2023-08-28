FROM quay.io/nabp/blockchain-interface:latest
WORKDIR /home/parity/

COPY --chown=parity:parity .circleci/docker/parity /home/parity

EXPOSE 8545
# wait for RMQ and topology service init
ENTRYPOINT sleep 30 && exec /home/parity/parity --config config.toml --no-warp
