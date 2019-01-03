extern crate num;
#[macro_use]
extern crate lazy_static;
extern crate crypto;
extern crate bit_vec;
extern crate hex;
extern crate byteorder;
extern crate bitintr;

use num::{BigUint, Zero};
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use byteorder::{ByteOrder, LittleEndian};
use bit_vec::BitVec;
use bitintr::Rbit;

const BN128_R: &[u8] = b"21888242871839275222246405745257275088548364400416034343698204186575808495617";
//const EDWARDS_R: &[u8] = b"1552511030102430251236801561344621993261920897571225601";
//const MNT4_R: &[u8] = b"475922286169261325753349249653048451545124878552823515553267735739164647307408490559963137";
//const MNT6_R: &[u8] = b"475922286169261325753349249653048451545124879242694725395555128576210262817955800483758081";

const MAX_BITLENGTH: u32 = 4096;

lazy_static! {
  static ref curve: BigUint = BigUint::parse_bytes(BN128_R, 10).unwrap();
  static ref coefficients: Vec<BigUint> = {
    let mask = BigUint::from(1u8) << curve.bits();
    let mut res = Vec::new();
    for i in 0u32..MAX_BITLENGTH {
      let mut buf1 = [0u8; 8];
      LittleEndian::write_u32(&mut buf1, i);
      for j in 0u32..std::u32::MAX {
        let mut buf2 = [0; 8];
        LittleEndian::write_u32(&mut buf2, j);
        let mut hasher = Sha512::new();
        hasher.input(&buf1);
        hasher.input(&buf2);
        let mut hash = [0u8; 64];
        hasher.result(&mut hash);
        let masked_hash = {
          let mut hash_vec = hash.to_vec();
          hash_vec.reverse();
          BigUint::from_bytes_be(&hash_vec) % &mask
        };
        if masked_hash < *curve {
          res.push(masked_hash);
          break;
        }
      }
    }
    res
  };
}

pub fn knapsack(input: &BitVec) -> Result<BigUint, &'static str> {
  let bit_length = input.len() as u32;
  if bit_length > MAX_BITLENGTH {
    return Err("Input bit length exceeds cached knapsack coefficients.");
  }
  let mut result = BigUint::zero();
  for bitset in input.iter().enumerate() {
    if bitset.1 {
      result += &coefficients[bitset.0];
      result = result % &*curve;
    }
  }
  Ok(result)
}

pub fn knapsack_msb254_slice<'a>(input1: &[u8], input2: &[u8]) -> Result<[u8; 32], &'static str> {
  let mut input_vec1 = BitVec::from_bytes(input1);
  let input_vec2 = BitVec::from_bytes(input2);
  input_vec1.truncate(254);
  input_vec1.extend(input_vec2.iter());
  let hash = knapsack(&input_vec1)?;
  let reversed: Vec<u8> = hash.to_bytes_le().as_slice().iter().map(|x| x.rbit()).collect();

  let mut res = [0u8; 32];
  res.copy_from_slice(&reversed);
  Ok(res)
}

#[cfg(test)]
mod tests {
  use {knapsack, knapsack_msb254_slice};
  use num::BigUint;
  use bit_vec::BitVec;

  #[test]
  fn compare_libsnarks_output() {
    struct TestRef {
      curve: &'static str,
      input: &'static [u8],
      input_length: u32,
      output: &'static [u8],
    }
    static REF: &'static [&'static TestRef] = &[
      &TestRef {curve: "bn128_r", input: b"ca40", input_length: 10, output: b"0x2acc4ff9318b68791608542324cf747fbbc33539af34ee64cd44a8b9cf276aed"},
      &TestRef {curve: "bn128_r", input: b"6300", input_length: 10, output: b"0x22b3e6a0afda243aebb4df8cbab41a6f866f025b01aea6054e7cc82eab201f93"},
      &TestRef {curve: "edwards_r", input: b"ca40", input_length: 10, output: b"0x23873783006679d60b97e14e435fd9596aaed6ae4cbde"},
      &TestRef {curve: "edwards_r", input: b"6300", input_length: 10, output: b"0x12fe0ea57011de5f6275c52c20a5306eeb0c6888ec1e9"},
      &TestRef {curve: "mnt4_r", input: b"ca40", input_length: 10, output: b"0xbc3419b722f9daccf64a847995f8e4782bfc4b578c1deefe14a99aead76ed400eca13314f"},
      &TestRef {curve: "mnt4_r", input: b"6300", input_length: 10, output: b"0x2ad2845358a024908c06c14b6f1aee6608f6f755d9bae9746947419db9ff8d85f75620ed691"},
      &TestRef {curve: "mnt6_r", input: b"ca40", input_length: 10, output: b"0xbc3419b722f9daccf64a847995f8e4782bf86d6ce351dc133cd14682f5b59fca1e747314f"},
      &TestRef {curve: "mnt6_r", input: b"6300", input_length: 10, output: b"0x2ad2845358a024908c06c14b6f1aee6608f6f377ef121d617e6f6949521dd451c087f42d691"}
    ];

    for val in REF {
      if val.curve != "bn128_r" {continue};
      let decoded = hex::decode(&val.input).unwrap();
      let input = BitVec::from_bytes(&decoded);
      let expected_output = BigUint::parse_bytes(&val.output[2..], 16).unwrap();

      let result = knapsack(&input).unwrap();

      assert!(result == expected_output, "Knapsack failed.");
    }

    let mut res_vec = knapsack_msb254_slice(&hex::decode(&b"ca40000000000000000000000000000000000000000000000000000000000000"[..]).unwrap(), &hex::decode(b"80").unwrap()).unwrap().to_vec();
    res_vec.reverse();
    assert!(hex::encode(res_vec) == "48618fb43ae57c27436b18ecddf3999397efcb59f9d9dcedfd046fe571079a21", "Knapsack 254 slice failed.");
  }
}

