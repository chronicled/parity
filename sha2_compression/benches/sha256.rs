#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate sha2_compression;

bench_digest!(sha2_compression::Sha256);
