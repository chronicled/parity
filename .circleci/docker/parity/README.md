# Parity set up

This parity node can be ran by itself as the only miner.

- The `./prv` directory contain a Blockchain database with 106 blocks already mined.
- The `start_from_index` value in RocksDB is set to 0 such that on start the Blockchain Interface should start its Backfill process. 