// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.
extern crate sha2_compression;
extern crate chron_knapsack;

use sha2_compression::{sha256_compress};

// Standard built-in contracts.

use std::cmp::{max, min};
use std::io::{self, Read};

use byteorder::{ByteOrder, BigEndian};
use parity_crypto::digest;
use num::{BigUint, Zero, One};

use hash::keccak;
use ethereum_types::{H256, U256};
use bytes::BytesRef;
use ethkey::{Signature, recover as ec_recover};
use ethjson;
use ethabi;
use ethabi::ParamType;
use ethabi::Token;
use snarkverifier;
use chron_knapsack::knapsack_msb254_slice;
use ::ff::{PrimeField, PrimeFieldRepr, BitIterator};
use ::pairing::bls12_381::{Fr, FrRepr, Bls12};
use ::sapling_crypto::{jubjub, pedersen_hash};
use ::sapling_crypto::jubjub::JubjubParams;
use ::sapling_crypto::circuit::multipack;
use self::jubjub::{JubjubEngine, JubjubBls12};
use ::bellman::groth16::{
    Proof,
    prepare_verifying_key,
    verify_proof,
		VerifyingKey,
};


/// Execution error.
#[derive(Debug)]
pub struct Error(pub &'static str);

impl From<&'static str> for Error {
	fn from(val: &'static str) -> Self {
		Error(val)
	}
}

impl Into<::vm::Error> for Error {
	fn into(self) -> ::vm::Error {
		::vm::Error::BuiltIn(self.0)
	}
}

impl From<ethabi::Error> for Error {
	fn from(val: ethabi::Error) -> Self {
	println!("Ethabi error {}", val.description());
		Error("Ethabi error")
	}
}



/// Native implementation of a built-in contract.
pub trait Impl: Send + Sync {
	/// execute this built-in on the given input, writing to the given output.
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error>;
}

/// A gas pricing scheme for built-in contracts.
pub trait Pricer: Send + Sync {
	/// The gas cost of running this built-in for the given input data.
	fn cost(&self, input: &[u8]) -> U256;
}

/// A linear pricing model. This computes a price using a base cost and a cost per-word.
struct Linear {
	base: usize,
	word: usize,
}

/// A special pricing model for modular exponentiation.
struct ModexpPricer {
	divisor: usize,
}

impl Pricer for Linear {
	fn cost(&self, input: &[u8]) -> U256 {
		U256::from(self.base) + U256::from(self.word) * U256::from((input.len() + 31) / 32)
	}
}

/// A alt_bn128_parinig pricing model. This computes a price using a base cost and a cost per pair.
struct AltBn128PairingPricer {
	base: usize,
	pair: usize,
}

impl Pricer for AltBn128PairingPricer {
	fn cost(&self, input: &[u8]) -> U256 {
		let cost = U256::from(self.base) + U256::from(self.pair) * U256::from(input.len() / 192);
		cost
	}
}

impl Pricer for ModexpPricer {
	fn cost(&self, input: &[u8]) -> U256 {
		let mut reader = input.chain(io::repeat(0));
		let mut buf = [0; 32];

		// read lengths as U256 here for accurate gas calculation.
		let mut read_len = || {
			reader.read_exact(&mut buf[..]).expect("reading from zero-extended memory cannot fail; qed");
			U256::from(H256::from_slice(&buf[..]))
		};
		let base_len = read_len();
		let exp_len = read_len();
		let mod_len = read_len();

		if mod_len.is_zero() && base_len.is_zero() {
			return U256::zero()
		}

		let max_len = U256::from(u32::max_value() / 2);
		if base_len > max_len || mod_len > max_len || exp_len > max_len {
			return U256::max_value();
		}
		let (base_len, exp_len, mod_len) = (base_len.low_u64(), exp_len.low_u64(), mod_len.low_u64());

		let m = max(mod_len, base_len);
		// read fist 32-byte word of the exponent.
		let exp_low = if base_len + 96 >= input.len() as u64 { U256::zero() } else {
			let mut buf = [0; 32];
			let mut reader = input[(96 + base_len as usize)..].chain(io::repeat(0));
			let len = min(exp_len, 32) as usize;
			reader.read_exact(&mut buf[(32 - len)..]).expect("reading from zero-extended memory cannot fail; qed");
			U256::from(H256::from_slice(&buf[..]))
		};

		let adjusted_exp_len = Self::adjusted_exp_len(exp_len, exp_low);

		let (gas, overflow) = Self::mult_complexity(m).overflowing_mul(max(adjusted_exp_len, 1));
		if overflow {
			return U256::max_value();
		}
		(gas / self.divisor as u64).into()
	}
}

impl ModexpPricer {
	fn adjusted_exp_len(len: u64, exp_low: U256) -> u64 {
		let bit_index = if exp_low.is_zero() { 0 } else { (255 - exp_low.leading_zeros()) as u64 };
		if len <= 32 {
			bit_index
		} else {
			8 * (len - 32) + bit_index
		}
	}

	fn mult_complexity(x: u64) -> u64 {
		match x {
			x if x <= 64 => x * x,
			x if x <= 1024 => (x * x) / 4 + 96 * x - 3072,
			x => (x * x) / 16 + 480 * x - 199680,
		}
	}
}

/// Pricing scheme, execution definition, and activation block for a built-in contract.
///
/// Call `cost` to compute cost for the given input, `execute` to execute the contract
/// on the given input, and `is_active` to determine whether the contract is active.
///
/// Unless `is_active` is true,
pub struct Builtin {
	pricer: Box<Pricer>,
	native: Box<Impl>,
	activate_at: u64,
}

impl Builtin {
	/// Simple forwarder for cost.
	pub fn cost(&self, input: &[u8]) -> U256 { self.pricer.cost(input) }

	/// Simple forwarder for execute.
	pub fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		self.native.execute(input, output)
	}

	/// Whether the builtin is activated at the given block number.
	pub fn is_active(&self, at: u64) -> bool { at >= self.activate_at }
}

impl From<ethjson::spec::Builtin> for Builtin {
	fn from(b: ethjson::spec::Builtin) -> Self {
		let pricer: Box<Pricer> = match b.pricing {
			ethjson::spec::Pricing::Linear(linear) => {
				Box::new(Linear {
					base: linear.base,
					word: linear.word,
				})
			}
			ethjson::spec::Pricing::Modexp(exp) => {
				Box::new(ModexpPricer {
					divisor: if exp.divisor == 0 {
						warn!("Zero modexp divisor specified. Falling back to default.");
						10
					} else {
						exp.divisor
					}
				})
			}
			ethjson::spec::Pricing::AltBn128Pairing(pricer) => {
				Box::new(AltBn128PairingPricer {
					base: pricer.base,
					pair: pricer.pair,
				})
			}
		};

		Builtin {
			pricer: pricer,
			native: ethereum_builtin(&b.name),
			activate_at: b.activate_at.map(Into::into).unwrap_or(0),
		}
	}
}

/// Ethereum built-in factory.
pub fn ethereum_builtin(name: &str) -> Box<Impl> {
	match name {
		"ZkSnark" => Box::new(ZkSnark) as Box<Impl>,
		"Sha256Compression" => Box::new(Sha256Compression) as Box<Impl>,
		"zk_snark_groth16_bls12_381" => Box::new(ZkSnarkGroth16Bls12_381) as Box<Impl>,
		"pedersen_hash" => Box::new(PedersenHash::<Bls12> {params: JubjubBls12::new()}) as Box<Impl>,
		"pedersen_comm" => Box::new(PedersenComm::<Bls12> {params: JubjubBls12::new()}) as Box<Impl>,
		"knapsack" => Box::new(Knapsack) as Box<Impl>,
		"identity" => Box::new(Identity) as Box<Impl>,
		"ecrecover" => Box::new(EcRecover) as Box<Impl>,
		"sha256" => Box::new(Sha256) as Box<Impl>,
		"ripemd160" => Box::new(Ripemd160) as Box<Impl>,
		"modexp" => Box::new(ModexpImpl) as Box<Impl>,
		"alt_bn128_add" => Box::new(Bn128AddImpl) as Box<Impl>,
		"alt_bn128_mul" => Box::new(Bn128MulImpl) as Box<Impl>,
		"alt_bn128_pairing" => Box::new(Bn128PairingImpl) as Box<Impl>,
		_ => panic!("invalid builtin name: {}", name),
	}
}

// Ethereum builtins:
//
// - The identity function
// - ec recovery
// - sha256
// - ripemd160
// - modexp (EIP198)

// Chronicled builtins:
// - ZkSnark
// - Sha256Compression
// - Knapsack CRH

#[derive(Debug)]
struct ZkSnark;

#[derive(Debug)]
struct ZkSnarkGroth16Bls12_381;

#[derive(Debug)]
struct PedersenHash<E: JubjubEngine> {
	params: E::Params,
}

#[derive(Debug)]
struct PedersenComm<E: JubjubEngine> {
	params: E::Params,
}

#[derive(Debug)]
struct Sha256Compression;

#[derive(Debug)]
struct Knapsack;

#[derive(Debug)]
struct Identity;

#[derive(Debug)]
struct EcRecover;

#[derive(Debug)]
struct Sha256;

#[derive(Debug)]
struct Ripemd160;

#[derive(Debug)]
struct ModexpImpl;

#[derive(Debug)]
struct Bn128AddImpl;

#[derive(Debug)]
struct Bn128MulImpl;

#[derive(Debug)]
struct Bn128PairingImpl;

impl Impl for ZkSnark {
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		for i in 0..output.len() {
			output[i] = 0;
		}
		let abitype = [ParamType::Bytes, ParamType::Bytes, ParamType::Bytes];
		let v = input[4..].to_vec();
		let decode = ethabi::decode(&abitype, &v);
		if let Ok(tokens) = decode {
			if tokens.len() == 3 {
				if let Token::Bytes(ref v1) = tokens[0] {
					if let Token::Bytes(ref v2) = tokens[1] {
						if let Token::Bytes(ref v3) = tokens[2] {
							let res = snarkverifier::verify(v1, v2, v3);

							if res {
								let out = [0; 32];
								output.write(0, &out);
								output.write(31, &[1]);
							}
						}
					}
				}
			}
		}
	Ok(())
	}
}

impl Impl for Sha256Compression {
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		for i in 0..output.len() {
			output[i] = 0;
		}
		let abitype = [ParamType::FixedBytes(32), ParamType::FixedBytes(32)];
		let v = input[4..].to_vec();
		let decode = ethabi::decode(&abitype, &v);
		if let Ok(tokens) = decode {
			if tokens.len() == 2 {
				if let Token::FixedBytes(ref left) = tokens[0] {
					if let Token::FixedBytes(ref right) = tokens[1] {
						let out = sha256_compress(left, right);
						output.write(0, &out);
					}
				}
			}
		}
	Ok(())
	}
}

impl Impl for ZkSnarkGroth16Bls12_381 {
	/// Verify zkSNARK proof for Groth16 on Bls 12 381
	/// Signature: (vk: bytes, primary_field: bytes32[], primary_bits: bytes, proof: bytes)
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		output.write(0, &[0u8; 32]);

		let abitype = [
			ParamType::Bytes,
			ParamType::Array(Box::new(ParamType::FixedBytes(32))),
			ParamType::Bytes,
			ParamType::Bytes,
		];

		let tokens = ethabi::decode(&abitype, &input[4..].to_vec())?;

		if tokens.len() != 4 {
			return Err(Error::from("Wrong number of inputs, expected 4"));
		}

		match tokens.as_slice() {
			&[
				Token::Bytes(ref vk), 
				Token::Array(ref primary_field), 
				Token::Bytes(ref primary_bits),
				Token::Bytes(ref proof),
			] => {

				println!("VK {:?}", &vk);
				let vk = VerifyingKey::<Bls12>::read(vk.as_slice())
					.map_err(|_| Error::from("Cannot read VK"))?;
					
				let proof = Proof::read(&proof[..])
					.map_err(|_| Error::from("Cannot read proof"))?;

				let primary_field: Vec<_> = primary_field.iter().map(|token| {
					match token {
						Token::FixedBytes(bytes32) => {
							let mut repr = FrRepr::default();
							repr.read_be(&bytes32[..]).expect("length is 32 bytes");
							Fr::from_repr(repr).map_err(|_| Error::from("PrimeFieldDecodingError"))
						},
						_ => Err(Error::from("Not a bytes32")),
					}
				}).collect::<Result<_, _>>()?; // .map_err(|_| Error::from("Cannot read field element"))

				// let primary_bits: Vec<_> = primary_bits.into_iter().cloned()
				// 	.map(|token| match token {
				// 		Token::FixedBytes(bytes32) => Ok(bytes32),
				// 		_ => Err("Not a bytes32")
				// 	}).collect::<Result<Vec<_>, _>>()?.into_iter().flatten().collect();
				
				let bits_le = multipack::bytes_to_bits_le(&primary_bits[..]);
    		let packed = multipack::compute_multipacking::<Bls12>(&bits_le[..]);

				let pvk = prepare_verifying_key(&vk);
				let result = verify_proof(
					&pvk,
					&proof,
					&[&primary_field[..], &packed[..]].concat()[..]
				).map_err(|_| Error::from("Cannot read field element"))?;
				println!("Primary All {:?}", [&primary_field[..], &packed[..]].concat());
				println!("Primary field {:?}", &primary_field);
				println!("Primary bits {:?}", &primary_bits);
				println!("VERIFYING PROOF {}", result);

				if result {
					output.write(31, &[1]);
				}
				Ok(())
			},
			_ => Err(Error("Incorrect input types, expected bytes, bytes32[], bytes32[]")),
		}
	}
}

fn get_personalization(personalization: &U256) -> Result<pedersen_hash::Personalization, Error> {
	let personalization_usize = personalization.as_usize();

	if personalization_usize >= 64 {
		return Err(Error("Personalization value is out of range"));
	}

	if personalization_usize == 63 {
		Ok(pedersen_hash::Personalization::NoteCommitment)
	} else {
		Ok(pedersen_hash::Personalization::MerkleTree(personalization_usize))
	}
}

impl<E: JubjubEngine> Impl for PedersenHash<E> where E::Params: Send + Sync {
	/// Hashes input of (personalization_6bits: uint8, left_fr_be: bytes32, right_fr_be: bytes32)
	/// returns result in BE encoding as bytes32 
	/// ignores method signature hash (i.e. first 4 bytes) of the input
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		output.write(0, &[0; 32]);

		let abitype = [ParamType::Uint(8), ParamType::FixedBytes(32), ParamType::FixedBytes(32)];
		let v = input[4..].to_vec();

		let tokens = ethabi::decode(&abitype, &v)?;
		if tokens.len() != 3 {
			return Err(Error::from("Wrong number of inputs, expected 3"));
		}

		match (&tokens[0], &tokens[1], &tokens[2])	{
			(
				Token::Uint(ref personalization_uint256), 
				Token::FixedBytes(ref left), 
				Token::FixedBytes(ref right)
			)	=> {
				let personalization = get_personalization(personalization_uint256)?;

				let mut left_fr = FrRepr::default();
				left_fr.read_be(left.as_slice()).expect("length is 32 bytes");
				let mut right_fr = FrRepr::default();
				right_fr.read_be(right.as_slice()).expect("length is 32 bytes");

				let mut left_bits: Vec<bool> = BitIterator::new(left_fr).collect();
				let mut right_bits: Vec<bool> = BitIterator::new(right_fr).collect();

				left_bits.reverse();
				right_bits.reverse();

				let hash = pedersen_hash::pedersen_hash::<E, _>(
						personalization,
						left_bits.into_iter()
								.take(Fr::NUM_BITS as usize)
								.chain(right_bits.into_iter().take(Fr::NUM_BITS as usize)),
						&self.params
				).into_xy().0;

				let mut out: Vec<u8> = vec![];
				hash.into_repr().write_be(&mut out).expect("Should write hash into bytes");
				output.write(0, &out);

				Ok(())
			},
			_ => Err(Error("Incorrect input types, expected uint8, bytes32, bytes32")),
		}
	}
}

impl<E: JubjubEngine> Impl for PedersenComm<E> where E::Params: Send + Sync {
	/// Hashes input of (personalization_6bits: uint8, value_le: bytes, trapdoor_fs_be: bytes32)
	/// returns result in BE encoding as bytes32 
	/// ignores method signature hash (i.e. first 4 bytes) of the input
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		output.write(0, &[0; 32]);

		let abitype = [ParamType::Uint(8), ParamType::Bytes, ParamType::FixedBytes(32)];
		let v = input[4..].to_vec();

		let tokens = ethabi::decode(&abitype, &v)?;
		if tokens.len() != 3 {
			return Err(Error::from("Wrong number of inputs, expected 3"));
		}

		match tokens.as_slice()	{
			&[
				Token::Uint(ref personalization_uint256), 
				Token::Bytes(ref value_le), 
				Token::FixedBytes(ref trapdoor_raw)
			]	=> {
				let personalization = get_personalization(personalization_uint256)?;

				let mut trapdoor_repr = <E::Fs as PrimeField>::Repr::default();
				trapdoor_repr.read_be(trapdoor_raw.as_slice()).expect("length is 32 bytes");
				let trapdoor = E::Fs::from_repr(trapdoor_repr).map_err(|_| "Incorrect tranpdoor Fs representation")?;
        
        // Compute the Pedersen hash of the coin contents
        let hash = pedersen_hash::pedersen_hash::<E, _>(
            personalization,
            value_le.into_iter()
                    .flat_map(|byte| {
                    	(0..8).map(move |i| ((byte >> i) & 1u8) == 1u8)
                    }),
            &self.params
        );

        // Compute final commitment
        let cm = &self.params.generator(jubjub::FixedGenerators::NoteCommitmentRandomness)
              .mul(trapdoor, &self.params)
              .add(&hash, &self.params)
              .into_xy().0;

				let mut result: Vec<u8> = vec![];
				cm.into_repr().write_be(&mut result).expect("Should write hash into bytes");
				output.write(0, &result);

				Ok(())
			},
			_ => Err(Error("Incorrect input types, expected uint8, bytes32, bytes32")),
		}
	}
}

impl Impl for Knapsack {
	/* knapsack(bytes param1, bytes param2)
	 *	 Calculates the knapsack CRH of param1 and param2.
	 *	 param1 is a 254-bit input, bit 0 is at the most significant position
	 *	 param2 is concatenated to the 254 bits of param1 and contains bits 254 to 510
	 */ 
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		let abitype = [ParamType::Bytes, ParamType::Bytes];
		// we don't use "tightly packed" data here for more convenience with solc
		let v = input[4..].to_vec();
		let decode = ethabi::decode(&abitype, &v)?;
		if decode.len() != 2 {
			return Err(Error::from("Wrong parameter count"));
		}
		match (&decode[0], &decode[1]) {
			(Token::Bytes(ref p1), Token::Bytes(ref p2)) => {
				let res = knapsack_msb254_slice(p1, p2).map_err(|e| Error(e))?;
				output.write(0, &res);
				Ok(())
			},
			_ => Err(Error::from("Wrong knapsack input")),
		}
	}
}


impl Impl for Identity {
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		output.write(0, input);
		Ok(())
	}
}

impl Impl for EcRecover {
	fn execute(&self, i: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		let len = min(i.len(), 128);

		let mut input = [0; 128];
		input[..len].copy_from_slice(&i[..len]);

		let hash = H256::from_slice(&input[0..32]);
		let v = H256::from_slice(&input[32..64]);
		let r = H256::from_slice(&input[64..96]);
		let s = H256::from_slice(&input[96..128]);

		let bit = match v[31] {
			27 | 28 if &v.0[..31] == &[0; 31] => v[31] - 27,
			_ => { return Ok(()); },
		};

		let s = Signature::from_rsv(&r, &s, bit);
		if s.is_valid() {
			if let Ok(p) = ec_recover(&s, &hash) {
				let r = keccak(p);
				output.write(0, &[0; 12]);
				output.write(12, &r[12..r.len()]);
			}
		}

		Ok(())
	}
}

impl Impl for Sha256 {
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		let d = digest::sha256(input);
		output.write(0, &*d);
		Ok(())
	}
}

impl Impl for Ripemd160 {
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		let hash = digest::ripemd160(input);
		output.write(0, &[0; 12][..]);
		output.write(12, &hash);
		Ok(())
	}
}

// calculate modexp: left-to-right binary exponentiation to keep multiplicands lower
fn modexp(mut base: BigUint, exp: Vec<u8>, modulus: BigUint) -> BigUint {
	const BITS_PER_DIGIT: usize = 8;

	// n^m % 0 || n^m % 1
	if modulus <= BigUint::one() {
		return BigUint::zero();
	}

	// normalize exponent
	let mut exp = exp.into_iter().skip_while(|d| *d == 0).peekable();

	// n^0 % m
	if let None = exp.peek() {
		return BigUint::one();
	}

	// 0^n % m, n > 0
	if base.is_zero() {
		return BigUint::zero();
	}

	base = base % &modulus;

	// Fast path for base divisible by modulus.
	if base.is_zero() { return BigUint::zero() }

	// Left-to-right binary exponentiation (Handbook of Applied Cryptography - Algorithm 14.79).
	// http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf
	let mut result = BigUint::one();

	for digit in exp {
		let mut mask = 1 << (BITS_PER_DIGIT - 1);

		for _ in 0..BITS_PER_DIGIT {
			result = &result * &result % &modulus;

			if digit & mask > 0 {
				result = result * &base % &modulus;
			}

			mask >>= 1;
		}
	}

	result
}

impl Impl for ModexpImpl {
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		let mut reader = input.chain(io::repeat(0));
		let mut buf = [0; 32];

		// read lengths as usize.
		// ignoring the first 24 bytes might technically lead us to fall out of consensus,
		// but so would running out of addressable memory!
		let mut read_len = |reader: &mut io::Chain<&[u8], io::Repeat>| {
			reader.read_exact(&mut buf[..]).expect("reading from zero-extended memory cannot fail; qed");
			BigEndian::read_u64(&buf[24..]) as usize
		};

		let base_len = read_len(&mut reader);
		let exp_len = read_len(&mut reader);
		let mod_len = read_len(&mut reader);

		// Gas formula allows arbitrary large exp_len when base and modulus are empty, so we need to handle empty base first.
		let r = if base_len == 0 && mod_len == 0 {
			BigUint::zero()
		} else {
			// read the numbers themselves.
			let mut buf = vec![0; max(mod_len, max(base_len, exp_len))];
			let mut read_num = |reader: &mut io::Chain<&[u8], io::Repeat>, len: usize| {
				reader.read_exact(&mut buf[..len]).expect("reading from zero-extended memory cannot fail; qed");
				BigUint::from_bytes_be(&buf[..len])
			};

			let base = read_num(&mut reader, base_len);

			let mut exp_buf = vec![0; exp_len];
			reader.read_exact(&mut exp_buf[..exp_len]).expect("reading from zero-extended memory cannot fail; qed");

			let modulus = read_num(&mut reader, mod_len);

			modexp(base, exp_buf, modulus)
		};

		// write output to given memory, left padded and same length as the modulus.
		let bytes = r.to_bytes_be();

		// always true except in the case of zero-length modulus, which leads to
		// output of length and value 1.
		if bytes.len() <= mod_len {
			let res_start = mod_len - bytes.len();
			output.write(res_start, &bytes);
		}

		Ok(())
	}
}

fn read_fr(reader: &mut io::Chain<&[u8], io::Repeat>) -> Result<::bn::Fr, Error> {
	let mut buf = [0u8; 32];

	reader.read_exact(&mut buf[..]).expect("reading from zero-extended memory cannot fail; qed");
	::bn::Fr::from_slice(&buf[0..32]).map_err(|_| Error::from("Invalid field element"))
}

fn read_point(reader: &mut io::Chain<&[u8], io::Repeat>) -> Result<::bn::G1, Error> {
	use bn::{Fq, AffineG1, G1, Group};

	let mut buf = [0u8; 32];

	reader.read_exact(&mut buf[..]).expect("reading from zero-extended memory cannot fail; qed");
	let px = Fq::from_slice(&buf[0..32]).map_err(|_| Error::from("Invalid point x coordinate"))?;

	reader.read_exact(&mut buf[..]).expect("reading from zero-extended memory cannot fail; qed");
	let py = Fq::from_slice(&buf[0..32]).map_err(|_| Error::from("Invalid point y coordinate"))?;
	Ok(
		if px == Fq::zero() && py == Fq::zero() {
			G1::zero()
		} else {
			AffineG1::new(px, py).map_err(|_| Error::from("Invalid curve point"))?.into()
		}
	)
}

impl Impl for Bn128AddImpl {
	// Can fail if any of the 2 points does not belong the bn128 curve
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		use bn::AffineG1;

		let mut padded_input = input.chain(io::repeat(0));
		let p1 = read_point(&mut padded_input)?;
		let p2 = read_point(&mut padded_input)?;

		let mut write_buf = [0u8; 64];
		if let Some(sum) = AffineG1::from_jacobian(p1 + p2) {
			// point not at infinity
			sum.x().to_big_endian(&mut write_buf[0..32]).expect("Cannot fail since 0..32 is 32-byte length");
			sum.y().to_big_endian(&mut write_buf[32..64]).expect("Cannot fail since 32..64 is 32-byte length");;
		}
		output.write(0, &write_buf);

		Ok(())
	}
}

impl Impl for Bn128MulImpl {
	// Can fail if first paramter (bn128 curve point) does not actually belong to the curve
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		use bn::AffineG1;

		let mut padded_input = input.chain(io::repeat(0));
		let p = read_point(&mut padded_input)?;
		let fr = read_fr(&mut padded_input)?;

		let mut write_buf = [0u8; 64];
		if let Some(sum) = AffineG1::from_jacobian(p * fr) {
			// point not at infinity
			sum.x().to_big_endian(&mut write_buf[0..32]).expect("Cannot fail since 0..32 is 32-byte length");
			sum.y().to_big_endian(&mut write_buf[32..64]).expect("Cannot fail since 32..64 is 32-byte length");;
		}
		output.write(0, &write_buf);
		Ok(())
	}
}

impl Impl for Bn128PairingImpl {
	/// Can fail if:
	///		- input length is not a multiple of 192
	///		- any of odd points does not belong to bn128 curve
	///		- any of even points does not belong to the twisted bn128 curve over the field F_p^2 = F_p[i] / (i^2 + 1)
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		if input.len() % 192 != 0 {
			return Err("Invalid input length, must be multiple of 192 (3 * (32*2))".into())
		}

		if let Err(err) = self.execute_with_error(input, output) {
			trace!("Pairining error: {:?}", err);
			return Err(err)
		}
		Ok(())
	}
}

impl Bn128PairingImpl {
	fn execute_with_error(&self, input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
		use bn::{AffineG1, AffineG2, Fq, Fq2, pairing, G1, G2, Gt, Group};

		let elements = input.len() / 192; // (a, b_a, b_b - each 64-byte affine coordinates)
		let ret_val = if input.len() == 0 {
			U256::one()
		} else {
			let mut vals = Vec::new();
			for idx in 0..elements {
				let a_x = Fq::from_slice(&input[idx*192..idx*192+32])
					.map_err(|_| Error::from("Invalid a argument x coordinate"))?;

				let a_y = Fq::from_slice(&input[idx*192+32..idx*192+64])
					.map_err(|_| Error::from("Invalid a argument y coordinate"))?;

				let b_a_y = Fq::from_slice(&input[idx*192+64..idx*192+96])
					.map_err(|_| Error::from("Invalid b argument imaginary coeff x coordinate"))?;

				let b_a_x = Fq::from_slice(&input[idx*192+96..idx*192+128])
					.map_err(|_| Error::from("Invalid b argument imaginary coeff y coordinate"))?;

				let b_b_y = Fq::from_slice(&input[idx*192+128..idx*192+160])
					.map_err(|_| Error::from("Invalid b argument real coeff x coordinate"))?;

				let b_b_x = Fq::from_slice(&input[idx*192+160..idx*192+192])
					.map_err(|_| Error::from("Invalid b argument real coeff y coordinate"))?;

				let b_a = Fq2::new(b_a_x, b_a_y);
				let b_b = Fq2::new(b_b_x, b_b_y);
				let b = if b_a.is_zero() && b_b.is_zero() {
					G2::zero()
				} else {
					G2::from(AffineG2::new(b_a, b_b).map_err(|_| Error::from("Invalid b argument - not on curve"))?)
				};
				let a = if a_x.is_zero() && a_y.is_zero() {
					G1::zero()
				} else {
					G1::from(AffineG1::new(a_x, a_y).map_err(|_| Error::from("Invalid a argument - not on curve"))?)
				};
				vals.push((a, b));
			};

			let mul = vals.into_iter().fold(Gt::one(), |s, (a, b)| s * pairing(a, b));

			if mul == Gt::one() {
				U256::one()
			} else {
				U256::zero()
			}
		};

		let mut buf = [0u8; 32];
		ret_val.to_big_endian(&mut buf);
		output.write(0, &buf);

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::{Builtin, Linear, ethereum_builtin, Pricer, ModexpPricer, modexp as me};
	use ethjson;
	use ethereum_types::U256;
	use bytes::BytesRef;
	use rustc_hex::FromHex;
	use num::{BigUint, Zero, One};
  use ethabi::Token;

	#[test]
	fn modexp_func() {
		// n^0 % m == 1
		let mut base = BigUint::parse_bytes(b"12345", 10).unwrap();
		let mut exp = BigUint::zero();
		let mut modulus = BigUint::parse_bytes(b"789", 10).unwrap();
		assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::one());

		// 0^n % m == 0
		base = BigUint::zero();
		exp = BigUint::parse_bytes(b"12345", 10).unwrap();
		modulus = BigUint::parse_bytes(b"789", 10).unwrap();
		assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::zero());

		// n^m % 1 == 0
		base = BigUint::parse_bytes(b"12345", 10).unwrap();
		exp = BigUint::parse_bytes(b"789", 10).unwrap();
		modulus = BigUint::one();
		assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::zero());

		// if n % d == 0, then n^m % d == 0
		base = BigUint::parse_bytes(b"12345", 10).unwrap();
		exp = BigUint::parse_bytes(b"789", 10).unwrap();
		modulus = BigUint::parse_bytes(b"15", 10).unwrap();
		assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::zero());

		// others
		base = BigUint::parse_bytes(b"12345", 10).unwrap();
		exp = BigUint::parse_bytes(b"789", 10).unwrap();
		modulus = BigUint::parse_bytes(b"97", 10).unwrap();
		assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::parse_bytes(b"55", 10).unwrap());
	}

	#[test]
	fn identity() {
		let f = ethereum_builtin("identity");

		let i = [0u8, 1, 2, 3];

		let mut o2 = [255u8; 2];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o2[..])).expect("Builtin should not fail");
		assert_eq!(i[0..2], o2);

		let mut o4 = [255u8; 4];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o4[..])).expect("Builtin should not fail");
		assert_eq!(i, o4);

		let mut o8 = [255u8; 8];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..])).expect("Builtin should not fail");
		assert_eq!(i, o8[..4]);
		assert_eq!([255u8; 4], o8[4..]);
	}

	#[test]
	fn sha256() {
		let f = ethereum_builtin("sha256");

		let i = [0u8; 0];

		let mut o = [255u8; 32];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap())[..]);

		let mut o8 = [255u8; 8];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..])).expect("Builtin should not fail");
		assert_eq!(&o8[..], &(FromHex::from_hex("e3b0c44298fc1c14").unwrap())[..]);

		let mut o34 = [255u8; 34];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o34[..])).expect("Builtin should not fail");
		assert_eq!(&o34[..], &(FromHex::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855ffff").unwrap())[..]);

		let mut ov = vec![];
		f.execute(&i[..], &mut BytesRef::Flexible(&mut ov)).expect("Builtin should not fail");
		assert_eq!(&ov[..], &(FromHex::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap())[..]);
	}

	#[test]
	fn ripemd160() {
		let f = ethereum_builtin("ripemd160");

		let i = [0u8; 0];

		let mut o = [255u8; 32];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31").unwrap())[..]);

		let mut o8 = [255u8; 8];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..])).expect("Builtin should not fail");
		assert_eq!(&o8[..], &(FromHex::from_hex("0000000000000000").unwrap())[..]);

		let mut o34 = [255u8; 34];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o34[..])).expect("Builtin should not fail");
		assert_eq!(&o34[..], &(FromHex::from_hex("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31ffff").unwrap())[..]);
	}

	#[test]
	fn ecrecover() {
		let f = ethereum_builtin("ecrecover");

		let i = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03").unwrap();

		let mut o = [255u8; 32];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("000000000000000000000000c08b5542d177ac6686946920409741463a15dddb").unwrap())[..]);

		let mut o8 = [255u8; 8];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..])).expect("Builtin should not fail");
		assert_eq!(&o8[..], &(FromHex::from_hex("0000000000000000").unwrap())[..]);

		let mut o34 = [255u8; 34];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o34[..])).expect("Builtin should not fail");
		assert_eq!(&o34[..], &(FromHex::from_hex("000000000000000000000000c08b5542d177ac6686946920409741463a15dddbffff").unwrap())[..]);

		let i_bad = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001a650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03").unwrap();
		let mut o = [255u8; 32];
		f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap())[..]);

		let i_bad = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b000000000000000000000000000000000000000000000000000000000000001b0000000000000000000000000000000000000000000000000000000000000000").unwrap();
		let mut o = [255u8; 32];
		f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap())[..]);

		let i_bad = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b").unwrap();
		let mut o = [255u8; 32];
		f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap())[..]);

		let i_bad = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000001b").unwrap();
		let mut o = [255u8; 32];
		f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap())[..]);

		let i_bad = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b000000000000000000000000000000000000000000000000000000000000001bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let mut o = [255u8; 32];
		f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap())[..]);

		// TODO: Should this (corrupted version of the above) fail rather than returning some address?
	/*	let i_bad = FromHex::from_hex("48173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03").unwrap();
		let mut o = [255u8; 32];
		f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..]));
		assert_eq!(&o[..], &(FromHex::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap())[..]);*/
	}

	#[test]
	fn modexp() {

		let f = Builtin {
			pricer: Box::new(ModexpPricer { divisor: 20 }),
			native: ethereum_builtin("modexp"),
			activate_at: 0,
		};

		// test for potential gas cost multiplication overflow
		{
			let input = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000003b27bafd00000000000000000000000000000000000000000000000000000000503c8ac3").unwrap();
			let expected_cost = U256::max_value();
			assert_eq!(f.cost(&input[..]), expected_cost.into());
		}

		// test for potential exp len overflow
		{
			let input = FromHex::from_hex("\
				00000000000000000000000000000000000000000000000000000000000000ff\
				2a1e530000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000"
				).unwrap();

			let mut output = vec![0u8; 32];
			let expected = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
			let expected_cost = U256::max_value();

			f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should fail");
			assert_eq!(output, expected);
			assert_eq!(f.cost(&input[..]), expected_cost.into());
		}

		// fermat's little theorem example.
		{
			let input = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000001\
				0000000000000000000000000000000000000000000000000000000000000020\
				0000000000000000000000000000000000000000000000000000000000000020\
				03\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
			).unwrap();

			let mut output = vec![0u8; 32];
			let expected = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
			let expected_cost = 13056;

			f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should not fail");
			assert_eq!(output, expected);
			assert_eq!(f.cost(&input[..]), expected_cost.into());
		}

		// second example from EIP: zero base.
		{
			let input = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000020\
				0000000000000000000000000000000000000000000000000000000000000020\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
			).unwrap();

			let mut output = vec![0u8; 32];
			let expected = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
			let expected_cost = 13056;

			f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should not fail");
			assert_eq!(output, expected);
			assert_eq!(f.cost(&input[..]), expected_cost.into());
		}

		// another example from EIP: zero-padding
		{
			let input = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000001\
				0000000000000000000000000000000000000000000000000000000000000002\
				0000000000000000000000000000000000000000000000000000000000000020\
				03\
				ffff\
				80"
			).unwrap();

			let mut output = vec![0u8; 32];
			let expected = FromHex::from_hex("3b01b01ac41f2d6e917c6d6a221ce793802469026d9ab7578fa2e79e4da6aaab").unwrap();
			let expected_cost = 768;

			f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should not fail");
			assert_eq!(output, expected);
			assert_eq!(f.cost(&input[..]), expected_cost.into());
		}

		// zero-length modulus.
		{
			let input = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000001\
				0000000000000000000000000000000000000000000000000000000000000002\
				0000000000000000000000000000000000000000000000000000000000000000\
				03\
				ffff"
			).unwrap();

			let mut output = vec![];
			let expected_cost = 0;

			f.execute(&input[..], &mut BytesRef::Flexible(&mut output)).expect("Builtin should not fail");
			assert_eq!(output.len(), 0); // shouldn't have written any output.
			assert_eq!(f.cost(&input[..]), expected_cost.into());
		}
	}

	#[test]
	fn bn128_add() {

		let f = Builtin {
			pricer: Box::new(Linear { base: 0, word: 0 }),
			native: ethereum_builtin("alt_bn128_add"),
			activate_at: 0,
		};

		// zero-points additions
		{
			let input = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000"
			).unwrap();

			let mut output = vec![0u8; 64];
			let expected = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000"
			).unwrap();

			f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should not fail");
			assert_eq!(output, expected);
		}

		// no input, should not fail
		{
			let mut empty = [0u8; 0];
			let input = BytesRef::Fixed(&mut empty);

			let mut output = vec![0u8; 64];
			let expected = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000"
			).unwrap();

			f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should not fail");
			assert_eq!(output, expected);
		}

		// should fail - point not on curve
		{
			let input = FromHex::from_hex("\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111"
			).unwrap();

			let mut output = vec![0u8; 64];

			let res = f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]));
			assert!(res.is_err(), "There should be built-in error here");
		}
	}

	#[test]
	fn bn128_mul() {

		let f = Builtin {
			pricer: Box::new(Linear { base: 0, word: 0 }),
			native: ethereum_builtin("alt_bn128_mul"),
			activate_at: 0,
		};

		// zero-point multiplication
		{
			let input = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000\
				0200000000000000000000000000000000000000000000000000000000000000"
			).unwrap();

			let mut output = vec![0u8; 64];
			let expected = FromHex::from_hex("\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000"
			).unwrap();

			f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should not fail");
			assert_eq!(output, expected);
		}

		// should fail - point not on curve
		{
			let input = FromHex::from_hex("\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				0f00000000000000000000000000000000000000000000000000000000000000"
			).unwrap();

			let mut output = vec![0u8; 64];

			let res = f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]));
			assert!(res.is_err(), "There should be built-in error here");
		}
	}

	fn builtin_pairing() -> Builtin {
		Builtin {
			pricer: Box::new(Linear { base: 0, word: 0 }),
			native: ethereum_builtin("alt_bn128_pairing"),
			activate_at: 0,
		}
	}

	fn empty_test(f: Builtin, expected: Vec<u8>) {
		let mut empty = [0u8; 0];
		let input = BytesRef::Fixed(&mut empty);

		let mut output = vec![0u8; expected.len()];

		f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).expect("Builtin should not fail");
		assert_eq!(output, expected);
	}

	fn error_test(f: Builtin, input: &[u8], msg_contains: Option<&str>) {
		let mut output = vec![0u8; 64];
		let res = f.execute(input, &mut BytesRef::Fixed(&mut output[..]));
		if let Some(msg) = msg_contains {
			if let Err(e) = res {
				if !e.0.contains(msg) {
					panic!("There should be error containing '{}' here, but got: '{}'", msg, e.0);
				}
			}
		} else {
			assert!(res.is_err(), "There should be built-in error here");
		}
	}

	fn bytes(s: &'static str) -> Vec<u8> {
		FromHex::from_hex(s).expect("static str should contain valid hex bytes")
	}

	#[test]
	fn bn128_pairing_empty() {
		// should not fail, because empty input is a valid input of 0 elements
		empty_test(
			builtin_pairing(),
			bytes("0000000000000000000000000000000000000000000000000000000000000001"),
		);
	}

	#[test]
	fn bn128_pairing_notcurve() {
		// should fail - point not on curve
		error_test(
			builtin_pairing(),
			&bytes("\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111"
			),
			Some("not on curve"),
		);
	}

	#[test]
	fn bn128_pairing_fragmented() {
		// should fail - input length is invalid
		error_test(
			builtin_pairing(),
			&bytes("\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				111111111111111111111111111111"
			),
			Some("Invalid input length"),
		);
	}

	#[test]
	#[should_panic]
	fn from_unknown_linear() {
		let _ = ethereum_builtin("foo");
	}

	#[test]
	fn is_active() {
		let pricer = Box::new(Linear { base: 10, word: 20} );
		let b = Builtin {
			pricer: pricer as Box<Pricer>,
			native: ethereum_builtin("identity"),
			activate_at: 100_000,
		};

		assert!(!b.is_active(99_999));
		assert!(b.is_active(100_000));
		assert!(b.is_active(100_001));
	}

	#[test]
	fn from_named_linear() {
		let pricer = Box::new(Linear { base: 10, word: 20 });
		let b = Builtin {
			pricer: pricer as Box<Pricer>,
			native: ethereum_builtin("identity"),
			activate_at: 1,
		};

		assert_eq!(b.cost(&[0; 0]), U256::from(10));
		assert_eq!(b.cost(&[0; 1]), U256::from(30));
		assert_eq!(b.cost(&[0; 32]), U256::from(30));
		assert_eq!(b.cost(&[0; 33]), U256::from(50));

		let i = [0u8, 1, 2, 3];
		let mut o = [255u8; 4];
		b.execute(&i[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(i, o);
	}

	#[test]
	fn from_json() {
		let b = Builtin::from(ethjson::spec::Builtin {
			name: "identity".to_owned(),
			pricing: ethjson::spec::Pricing::Linear(ethjson::spec::Linear {
				base: 10,
				word: 20,
			}),
			activate_at: None,
		});

		assert_eq!(b.cost(&[0; 0]), U256::from(10));
		assert_eq!(b.cost(&[0; 1]), U256::from(30));
		assert_eq!(b.cost(&[0; 32]), U256::from(30));
		assert_eq!(b.cost(&[0; 33]), U256::from(50));

		let i = [0u8, 1, 2, 3];
		let mut o = [255u8; 4];
		b.execute(&i[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(i, o);
	}

	#[test]
	fn knapsack() {
		let f = ethereum_builtin("knapsack");
		let mut i = FromHex::from_hex("01020304").unwrap();
		i.append(&mut ethabi::encode(&vec![Token::Bytes(FromHex::from_hex("ca40000000000000000000000000000000000000000000000000000000000000").unwrap()), Token::Bytes(FromHex::from_hex("80").unwrap())]));

		let mut o = [255u8; 32];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o[..])).expect("Builtin should not fail");
		assert_eq!(&o[..], &(FromHex::from_hex("219a0771e56f04fdeddcd9f959cbef979399f3ddec186b43277ce53ab48f6148").unwrap())[..]);

		let mut o8 = [255u8; 8];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..])).expect("Builtin should not fail");
		assert_eq!(&o8[..], &(FromHex::from_hex("219a0771e56f04fd").unwrap())[..]);

		let mut o34 = [255u8; 34];
		f.execute(&i[..], &mut BytesRef::Fixed(&mut o34[..])).expect("Builtin should not fail");
		assert_eq!(&o34[..], &(FromHex::from_hex("219a0771e56f04fdeddcd9f959cbef979399f3ddec186b43277ce53ab48f6148ffff").unwrap())[..]);

		let mut ov = vec![];
		f.execute(&i[..], &mut BytesRef::Flexible(&mut ov)).expect("Builtin should not fail");
		assert_eq!(&ov[..], &(FromHex::from_hex("219a0771e56f04fdeddcd9f959cbef979399f3ddec186b43277ce53ab48f6148").unwrap())[..]);

		let i_1024 = [255u8; 1024];
		let mut i_1024_rlp = FromHex::from_hex("01020304").unwrap();
		i_1024_rlp.append(&mut ethabi::encode(&vec![Token::Bytes(i_1024.to_vec()), Token::Bytes(i_1024.to_vec())]));
		f.execute(&i_1024_rlp[..], &mut BytesRef::Flexible(&mut ov)).expect_err("Builtin should fail if input is too long");
	}

	#[test]
	fn zk_snark_groth16_bls12_381() {
		let verifier = ethereum_builtin("zk_snark_groth16_bls12_381");

		let vk = vec![14, 237, 126, 27, 233, 48, 89, 199, 170, 209, 70, 133, 14, 121, 138, 189, 179, 213, 69, 232, 235, 153, 237, 223, 222, 255, 108, 30, 159, 71, 253, 104, 229, 132, 93, 176, 3, 99, 93, 21, 255, 193, 215, 123, 164, 210, 168, 171, 9, 156, 87, 0, 192, 81, 72, 236, 9, 158, 35, 182, 77, 14, 39, 214, 141, 118, 193, 55, 177, 100, 73, 9, 167, 63, 218, 10, 77, 47, 164, 128, 20, 75, 251, 116, 7, 187, 186, 249, 57, 219, 243, 28, 17, 232, 108, 36, 7, 81, 249, 82, 247, 30, 87, 255, 173, 178, 196, 195, 95, 121, 187, 14, 53, 187, 150, 19, 236, 67, 222, 208, 228, 145, 221, 80, 157, 132, 133, 250, 185, 176, 5, 104, 116, 242, 207, 185, 9, 4, 15, 94, 116, 128, 166, 56, 23, 120, 69, 16, 201, 124, 70, 140, 14, 150, 87, 210, 243, 174, 206, 172, 118, 104, 67, 169, 9, 183, 11, 72, 143, 104, 3, 211, 10, 44, 170, 155, 10, 84, 75, 156, 252, 177, 148, 186, 70, 135, 180, 147, 251, 220, 230, 176, 18, 202, 77, 201, 51, 67, 125, 12, 168, 171, 109, 43, 130, 34, 158, 154, 16, 83, 120, 18, 139, 121, 232, 29, 144, 94, 66, 31, 198, 167, 93, 154, 244, 200, 137, 121, 175, 229, 185, 102, 144, 84, 63, 216, 207, 244, 192, 45, 15, 213, 13, 108, 181, 32, 62, 135, 87, 222, 27, 172, 74, 160, 217, 93, 6, 51, 27, 33, 16, 85, 165, 8, 166, 53, 103, 19, 247, 112, 226, 99, 139, 60, 23, 50, 196, 117, 8, 255, 32, 11, 187, 84, 181, 186, 18, 64, 1, 153, 184, 186, 122, 57, 17, 196, 141, 141, 146, 225, 83, 19, 64, 208, 25, 246, 250, 5, 68, 96, 118, 229, 80, 188, 97, 122, 74, 169, 140, 194, 19, 31, 235, 207, 197, 125, 231, 223, 59, 42, 91, 178, 48, 202, 147, 47, 17, 162, 185, 218, 178, 211, 1, 243, 51, 110, 44, 70, 29, 174, 3, 137, 142, 70, 112, 121, 205, 98, 20, 171, 90, 196, 47, 4, 147, 92, 70, 32, 165, 188, 150, 163, 179, 7, 23, 166, 49, 6, 47, 190, 131, 60, 5, 45, 20, 211, 135, 184, 122, 62, 103, 59, 106, 80, 38, 225, 13, 114, 75, 145, 13, 171, 244, 132, 101, 38, 41, 115, 217, 234, 20, 16, 60, 83, 216, 121, 108, 45, 35, 115, 229, 105, 44, 154, 136, 60, 99, 71, 162, 225, 189, 204, 22, 7, 227, 29, 48, 97, 166, 55, 113, 92, 45, 39, 139, 188, 162, 48, 179, 226, 150, 95, 57, 35, 214, 135, 106, 160, 98, 248, 215, 78, 111, 65, 66, 169, 207, 58, 103, 137, 164, 10, 116, 111, 25, 56, 152, 11, 233, 185, 16, 141, 222, 242, 203, 16, 178, 137, 59, 248, 207, 221, 187, 48, 150, 5, 204, 122, 4, 186, 179, 209, 73, 84, 54, 191, 3, 137, 158, 195, 5, 205, 162, 58, 8, 1, 104, 177, 67, 124, 177, 144, 80, 84, 87, 148, 6, 161, 5, 166, 39, 120, 138, 154, 142, 131, 204, 1, 41, 184, 195, 59, 70, 120, 18, 209, 112, 246, 171, 95, 240, 164, 94, 250, 98, 97, 191, 250, 113, 98, 105, 200, 198, 43, 10, 8, 51, 27, 154, 11, 71, 36, 214, 154, 13, 217, 13, 225, 82, 79, 66, 230, 94, 53, 28, 218, 129, 170, 41, 144, 86, 18, 218, 14, 172, 155, 130, 227, 210, 245, 77, 120, 46, 135, 59, 2, 81, 71, 46, 43, 161, 63, 34, 74, 64, 222, 55, 124, 0, 69, 241, 0, 89, 54, 20, 65, 50, 27, 54, 125, 211, 128, 126, 248, 129, 223, 227, 240, 73, 180, 75, 156, 152, 7, 193, 81, 250, 42, 21, 165, 100, 52, 204, 170, 97, 139, 111, 160, 182, 3, 246, 81, 133, 88, 46, 34, 236, 214, 215, 205, 133, 168, 24, 194, 20, 70, 221, 210, 100, 121, 240, 31, 101, 166, 170, 216, 123, 42, 181, 75, 78, 189, 71, 225, 199, 62, 73, 40, 67, 100, 145, 51, 223, 56, 182, 224, 65, 27, 174, 203, 201, 255, 120, 91, 8, 184, 166, 51, 226, 249, 15, 87, 28, 128, 235, 76, 200, 1, 105, 6, 186, 194, 63, 216, 175, 24, 252, 108, 78, 109, 238, 210, 215, 167, 7, 31, 211, 210, 244, 66, 201, 163, 135, 249, 122, 213, 16, 190, 136, 245, 31, 168, 61, 142, 247, 240, 106, 190, 15, 166, 114, 39, 255, 67, 2, 240, 90, 121, 26, 118, 5, 187, 14, 73, 89, 84, 209, 181, 255, 220, 29, 76, 255, 89, 49, 168, 41, 181, 130, 158, 35, 22, 150, 145, 211, 117, 20, 200, 224, 108, 101, 165, 47, 249, 131, 213, 13, 206, 18, 63, 40, 99, 214, 139, 221, 85, 241, 121, 192, 17, 181, 164, 47, 11, 22, 202, 201, 107, 20, 253, 238, 50, 235, 42, 140, 10, 53, 29, 41, 237, 7, 146, 17, 245, 115, 130, 107, 91, 209, 121, 83, 101, 146, 3, 0, 0, 0, 9, 17, 183, 8, 149, 255, 255, 234, 161, 12, 108, 56, 198, 27, 108, 214, 60, 10, 145, 112, 233, 77, 198, 122, 64, 29, 203, 206, 45, 103, 111, 107, 42, 189, 254, 5, 244, 14, 4, 43, 85, 36, 50, 130, 182, 112, 249, 131, 212, 10, 45, 137, 142, 7, 109, 234, 166, 215, 0, 61, 237, 92, 174, 80, 159, 172, 53, 198, 100, 127, 105, 32, 22, 58, 30, 160, 177, 116, 172, 131, 217, 168, 231, 196, 153, 111, 43, 123, 153, 70, 220, 65, 184, 230, 104, 48, 19, 24, 173, 6, 0, 248, 104, 144, 243, 40, 189, 66, 116, 64, 255, 199, 247, 120, 112, 213, 214, 245, 78, 158, 191, 47, 175, 29, 149, 168, 215, 6, 72, 253, 77, 144, 94, 125, 178, 235, 241, 88, 241, 219, 179, 58, 78, 47, 123, 0, 3, 138, 32, 165, 29, 92, 220, 14, 205, 4, 65, 46, 159, 217, 71, 176, 50, 230, 140, 69, 120, 44, 237, 38, 115, 90, 233, 104, 156, 97, 118, 177, 104, 230, 18, 81, 245, 129, 78, 2, 230, 85, 109, 222, 250, 133, 222, 14, 19, 182, 132, 43, 42, 73, 208, 216, 106, 243, 180, 126, 186, 232, 140, 234, 153, 154, 192, 220, 173, 65, 103, 189, 153, 238, 91, 253, 72, 121, 123, 141, 103, 173, 165, 179, 184, 217, 192, 64, 222, 204, 81, 135, 97, 4, 192, 15, 188, 189, 212, 198, 114, 78, 150, 43, 57, 67, 65, 33, 28, 233, 102, 82, 227, 80, 170, 177, 139, 149, 155, 180, 122, 254, 38, 60, 175, 244, 116, 8, 97, 193, 55, 158, 216, 144, 218, 2, 35, 96, 129, 141, 13, 249, 25, 25, 112, 52, 160, 131, 148, 247, 142, 0, 93, 60, 208, 197, 6, 186, 216, 156, 118, 254, 119, 75, 199, 168, 175, 181, 147, 151, 137, 128, 186, 80, 42, 145, 180, 27, 197, 177, 47, 250, 216, 87, 67, 205, 92, 149, 200, 156, 162, 20, 120, 37, 100, 180, 140, 156, 84, 83, 162, 14, 91, 214, 77, 71, 65, 11, 183, 151, 62, 209, 14, 40, 203, 145, 249, 210, 181, 180, 10, 43, 74, 187, 184, 232, 223, 192, 104, 79, 48, 52, 67, 78, 225, 183, 45, 90, 220, 24, 201, 78, 184, 56, 175, 210, 93, 90, 188, 51, 246, 125, 200, 26, 196, 101, 19, 169, 237, 88, 68, 71, 122, 28, 158, 34, 34, 63, 153, 215, 244, 91, 233, 195, 147, 57, 202, 120, 28, 113, 17, 7, 181, 32, 137, 69, 185, 13, 21, 174, 6, 6, 179, 93, 246, 220, 204, 143, 122, 124, 169, 150, 83, 161, 231, 241, 43, 165, 64, 251, 155, 230, 5, 253, 228, 55, 253, 218, 50, 2, 156, 118, 161, 202, 197, 118, 86, 131, 116, 203, 88, 37, 195, 196, 235, 4, 83, 198, 147, 27, 74, 148, 141, 40, 28, 247, 89, 249, 145, 132, 92, 1, 178, 113, 43, 250, 82, 141, 170, 159, 191, 32, 210, 141, 150, 217, 65, 34, 84, 82, 70, 195, 138, 106, 146, 53, 48, 25, 143, 240, 7, 137, 183, 9, 190, 244, 87, 92, 180, 165, 125, 168, 185, 227, 95, 229, 86, 239, 41, 158, 57, 41, 180, 234, 255, 16, 221, 217, 199, 39, 176, 136, 37, 110, 30, 10, 38, 121, 181, 216, 119, 90, 56, 166, 116, 100, 141, 52, 103, 156, 208, 1, 152, 217, 236, 76, 175, 193, 215, 98, 71, 199, 234, 205, 10, 130, 137, 192, 114, 224, 169, 207, 236, 100, 159, 245, 178, 231, 62, 5, 171, 23, 96, 169, 138, 52, 17, 21, 121, 187, 102, 130, 196, 183, 149, 212, 105, 189, 155, 17, 117, 9, 228, 227, 206, 18, 154, 182, 150, 174, 135, 198, 204, 169, 155, 35, 205, 66, 182, 58, 134, 220, 79, 23, 249, 142, 96, 178, 99, 36, 132, 127, 196, 122, 33, 56, 86, 152, 205, 29, 238, 83, 116, 203, 221, 237, 39, 20, 136, 208, 192, 255, 22, 166, 56, 25, 6, 21, 63, 175, 97, 190, 130, 162, 198, 127, 125, 41, 244, 83, 52, 247, 148, 118, 37, 130, 182, 65, 131, 255, 113, 107, 61, 38, 80, 147, 201, 178, 53, 3, 115, 119, 72, 112, 95, 24, 213, 21, 217, 156, 173, 24, 70, 73, 106, 236, 17, 253, 137, 38, 56, 218, 244, 77, 253, 183, 111, 18, 62, 47, 240, 150, 200, 93, 211, 204, 0, 132, 136, 205, 146, 168, 33, 253, 160, 196, 87, 172, 39, 134, 241, 26, 209, 12, 7, 49, 226, 124, 169, 83, 236, 43, 33, 103, 27, 64, 147, 78, 61, 225, 60, 13, 4, 62, 61, 4, 50, 217, 193, 8, 155, 173, 155, 178, 16, 234, 131, 112, 231, 194, 162, 196, 119, 111, 207, 39, 141, 150, 51, 105, 126, 13, 85, 57, 85, 11, 1, 64, 180, 174, 226, 66, 61, 162, 211, 39, 200, 194, 164, 211, 111, 199, 175, 95, 120, 51, 6, 183, 124, 80, 88, 100, 98, 125, 40, 167, 49, 230, 87, 68, 43, 40, 39, 68, 235, 210, 16, 39, 63];
		let primary_field = vec![
			vec![37, 227, 103, 61, 87, 222, 132, 239, 3, 98, 179, 143, 122, 179, 231, 88, 63, 82, 2, 169, 57, 245, 160, 29, 202, 207, 102, 36, 98, 123, 15, 183],
			vec![31, 216, 140, 63, 2, 149, 111, 251, 68, 160, 222, 204, 103, 148, 96, 248, 219, 151, 129, 236, 77, 127, 128, 138, 226, 47, 74, 144, 220, 187, 228, 144],
			vec![21, 130, 90, 222, 135, 14, 45, 230, 29, 242, 77, 2, 50, 110, 155, 158, 98, 32, 238, 249, 160, 61, 203, 242, 236, 250, 187, 201, 116, 159, 221, 253]
		];
		let primary_bits = vec![175, 5, 70, 109, 235, 66, 102, 203, 248, 169, 236, 139, 186, 63, 158, 133, 42, 128, 95, 144, 207, 148, 145, 251, 196, 205, 170, 92, 17, 57, 153, 173, 16, 11, 183, 223, 123, 37, 67, 64, 153, 41, 82, 130, 86, 9, 29, 71, 27, 187, 239, 79, 250, 201, 37, 195, 212, 50, 26, 146, 105, 188, 104, 211, 4, 0, 0, 0, 0, 0, 0, 0, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 224, 58, 150, 177, 73, 199, 148, 145, 64, 122, 255, 26, 37, 227, 180, 173, 151, 144, 79, 56, 158, 135, 152, 212, 149, 9, 60, 134, 73, 227, 249, 87];
		let proof = vec![185, 205, 25, 162, 137, 18, 112, 7, 114, 147, 42, 147, 238, 186, 75, 181, 213, 252, 236, 64, 45, 145, 102, 35, 132, 160, 228, 134, 44, 205, 19, 67, 3, 223, 151, 92, 190, 47, 132, 86, 8, 230, 89, 22, 29, 124, 92, 73, 148, 60, 187, 120, 23, 198, 188, 236, 151, 174, 2, 59, 63, 194, 77, 243, 28, 252, 115, 133, 26, 208, 48, 130, 191, 10, 141, 246, 34, 239, 161, 197, 79, 179, 101, 245, 247, 78, 156, 25, 175, 211, 223, 95, 59, 191, 161, 107, 3, 78, 252, 148, 84, 61, 133, 101, 158, 221, 16, 2, 206, 33, 62, 151, 0, 105, 72, 111, 227, 28, 18, 115, 155, 130, 137, 14, 163, 115, 159, 250, 9, 76, 94, 113, 22, 59, 172, 245, 168, 147, 107, 8, 198, 159, 186, 214, 151, 12, 120, 179, 71, 93, 148, 153, 12, 69, 63, 63, 47, 73, 143, 200, 1, 98, 213, 149, 28, 51, 219, 90, 118, 55, 188, 84, 229, 59, 233, 169, 212, 169, 32, 71, 195, 233, 66, 120, 1, 124, 44, 168, 160, 7, 202, 253];
		
		let encoded = ethabi::encode(&[
			Token::Bytes(vk), 
			Token::Array(primary_field.into_iter().map(Token::FixedBytes).collect()), 
			Token::Bytes(primary_bits),
			Token::Bytes(proof)
		]);

		let mut expected = [0u8; 32];
		expected[31] = 1;

		let input = [&[0u8, 0, 0, 0], &encoded[..]].concat();

		let mut output = [0; 32];
		verifier.execute(&input, &mut BytesRef::Fixed(&mut output[..]))
			.expect("zk_snark_groth16_bls12_381 should not fail");

		assert_eq!(output, expected);
	}

	#[test]
	fn pedersen_hash() {
		let hasher = ethereum_builtin("pedersen_hash");

		let mut personalization = [0u8; 32];
		personalization[31] = 5;

		let left = [20, 57, 102, 236, 193, 168, 69, 108, 127, 122, 153, 30, 53, 133, 37, 122, 66, 233, 174, 232, 118, 58, 9, 121, 54, 59, 76, 193, 163, 33, 27, 239];
		let right = [65, 16, 64, 54, 40, 169, 42, 229, 49, 113, 92, 112, 114, 121, 65, 246, 95, 143, 111, 215, 37, 17, 108, 60, 254, 76, 38, 220, 236, 125, 100, 253];
		let result: [u8; 32] = [100, 98, 77, 206, 219, 123, 20, 61, 51, 246, 201, 32, 0, 66, 252, 151, 241, 133, 64, 30, 72, 207, 195, 141, 77, 71, 38, 13, 167, 160, 105, 194];

		let input = [&[0u8, 0, 0, 0], &personalization[..], &left, &right].concat();

		let mut output = [0; 32];
		hasher.execute(&input, &mut BytesRef::Fixed(&mut output[..])).expect("pedersen_hash should not fail");
		assert_eq!(output, result);
	}

	#[test]
	fn pedersen_comm() {
		let hasher = ethereum_builtin("pedersen_comm");

		let personalization = U256::from(63);
		let value = vec![161, 107, 129, 105, 199, 33, 22, 108, 95, 83, 213, 114, 123, 131, 178, 65, 62, 161, 6, 66, 227, 255, 11, 81, 158, 242, 124, 212, 39, 79, 75, 218, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32];
		let trapdoor_be = vec![1, 76, 30, 119, 167, 183, 241, 39, 230, 238, 209, 243, 16, 171, 234, 205, 84, 189, 63, 171, 140, 240, 132, 238, 216, 50, 212, 178, 75, 185, 149, 85];
		
		let encoded = ethabi::encode(&[
			Token::Uint(personalization), 
			Token::Bytes(value),
			Token::FixedBytes(trapdoor_be)
		]);

		let expected: [u8; 32] = [84, 14, 156, 210, 49, 211, 168, 181, 247, 44, 56, 8, 237, 170, 252, 232, 179, 175, 114, 180, 15, 208, 45, 74, 12, 154, 36, 159, 80, 137, 86, 141];

		let input = [&[0u8, 0, 0, 0], &encoded[..]].concat();

		let mut output = [0; 32];
		hasher.execute(&input, &mut BytesRef::Fixed(&mut output[..])).expect("pedersen_hash should not fail");
		assert_eq!(output, expected);
	}
}
