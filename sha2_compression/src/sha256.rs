use digest;
use generic_array::GenericArray;
use block_buffer::BlockBuffer;
use generic_array::typenum::{U28, U32, U64};
use byte_tools::write_u32v_be;

use consts::{STATE_LEN, H224, H256};

#[cfg(not(feature = "asm"))]
use sha256_utils::compress256;
#[cfg(feature = "asm")]
use sha2_asm::compress256;

type BlockSize = U64;
pub type Block = GenericArray<u8, BlockSize>;

/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Clone, Copy)]
pub struct Engine256State {
    pub h: [u32; 8],
}

impl Engine256State {
    fn new(h: &[u32; STATE_LEN]) -> Engine256State { Engine256State { h: *h } }

    pub fn process_block(&mut self, data: &Block) {
        compress256(&mut self.h, data);
    }
}

/// A structure that keeps track of the state of the Sha-256 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone, Copy)]
pub struct Engine256 {
    len: u64,
    buffer: BlockBuffer<BlockSize>,
    pub state: Engine256State,
}

impl Engine256 {
    fn new(h: &[u32; STATE_LEN]) -> Engine256 {
        Engine256 {
            len: 0,
            buffer: Default::default(),
            state: Engine256State::new(h),
        }
    }

    fn input(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.len += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |input| self_state.process_block(input));
    }

    fn finish(&mut self) {
        let self_state = &mut self.state;
        let l = (self.len<<3).to_be();
        self.buffer.len_padding(l, |input| self_state.process_block(input));
    }
}


/// The SHA-256 hash algorithm with the SHA-256 initial hash value.
#[derive(Clone, Copy)]
pub struct Sha256 {
    pub engine: Engine256,
}

impl Default for Sha256 {
    fn default() -> Self { Sha256 { engine: Engine256::new(&H256) } }
}

impl digest::BlockInput for Sha256 {
    type BlockSize = BlockSize;
}

impl digest::Input for Sha256 {
    fn process(&mut self, msg: &[u8]) { self.engine.input(msg); }
}

impl digest::FixedOutput for Sha256 {
    type OutputSize = U32;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        write_u32v_be(&mut out, &self.engine.state.h);
        out
    }
}

/// The SHA-256 hash algorithm with the SHA-224 initial hash value. The result
/// is truncated to 224 bits.
#[derive(Clone, Copy)]
pub struct Sha224 {
    engine: Engine256,
}

impl Default for Sha224 {
    fn default() -> Self { Sha224 { engine: Engine256::new(&H224) } }
}

impl digest::BlockInput for Sha224 {
    type BlockSize = BlockSize;
}

impl digest::Input for Sha224 {
    fn process(&mut self, msg: &[u8]) { self.engine.input(msg); }
}

impl digest::FixedOutput for Sha224 {
    type OutputSize = U28;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        write_u32v_be(&mut out[..28], &self.engine.state.h[..7]);
        out
    }
}
