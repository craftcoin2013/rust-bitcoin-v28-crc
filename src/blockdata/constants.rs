// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use prelude::*;

use core::default::Default;
use hash_types::{BlockHash, TxMerkleNode};

use hashes::hex::{HexIterator, Error as HexError, FromHex};
use hashes::sha256d;
use blockdata::opcodes;
use blockdata::script;
use blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn};
use blockdata::block::{Block, BlockHeader};
use blockdata::witness::Witness;
use network::constants::Network;
use util::uint::Uint256;

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub const TARGET_BLOCK_SPACING: u32 = 60;
/// How many blocks between diffchanges
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 57; // 0x00
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 16; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 5; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 100_000;

/// In Bitcoind this is insanely described as ~((u256)0 >> 32)
pub fn max_target(_: Network) -> Uint256 {
    Uint256::from_u64(0xFFFF).unwrap() << 208
}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    100_000_000 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_scriptint(486604799)
                                          .push_scriptint(4)
                                          .push_slice(b"Big Brother Is Watching You #PRISM")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: MAX_SEQUENCE,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes: Result<Vec<u8>, HexError> =
        HexIterator::new("00").unwrap()
            .collect();
    let out_script = script::Builder::new()
        .push_slice(script_bytes.unwrap().as_slice())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 0 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    // Use fixed merkle root instead of calculating from transaction
    let merkle_root_hash = sha256d::Hash::from_hex("71af8a6b906ecef9cf9cb05a593639f6bd2db7cefb9b2ceaed9065b97b01fa35").unwrap();
    let merkle_root = TxMerkleNode::from_hash(merkle_root_hash);
    let empty_block_hash: BlockHash = hash.into();
    
    match network {
        Network::Bitcoin => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1371051790,
                    bits: 0x1e0ffff0,
                    nonce: 1848112,
                    coinbase_txn: bitcoin_genesis_tx(),
                    block_hash: empty_block_hash,
                    coinbase_branch_hashes: vec![0; 1],
                    coinbase_branch_side_mask: 0,
                    blockchain_branch_hashes: vec![0; 1],
                    blockchain_branch_side_mask: 0,
                    parent_version: 0,
                    parent_prev_blockhash: empty_block_hash,
                    parent_merkle_root: merkle_root,
                    parent_time: 0,
                    parent_bits: 0,
                    parent_nonce: 0
                },
                txdata,
            }
        }
        Network::Testnet => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1371040850,
                    bits: 0x1e0ffff0,
                    nonce: 1521622,
                    coinbase_txn: bitcoin_genesis_tx(),
                    block_hash: empty_block_hash,
                    coinbase_branch_hashes: vec![0; 1],
                    coinbase_branch_side_mask: 0,
                    blockchain_branch_hashes: vec![0; 1],
                    blockchain_branch_side_mask: 0,
                    parent_version: 0,
                    parent_prev_blockhash: empty_block_hash,
                    parent_merkle_root: merkle_root,
                    parent_time: 0,
                    parent_bits: 0,
                    parent_nonce: 0
                },
                txdata,
            }
        }
        Network::Signet => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1371040850,
                    bits: 0x1e0ffff0,
                    nonce: 1521622,
                    coinbase_txn: bitcoin_genesis_tx(),
                    block_hash: empty_block_hash,
                    coinbase_branch_hashes: vec![0; 1],
                    coinbase_branch_side_mask: 0,
                    blockchain_branch_hashes: vec![0; 1],
                    blockchain_branch_side_mask: 0,
                    parent_version: 0,
                    parent_prev_blockhash: empty_block_hash,
                    parent_merkle_root: merkle_root,
                    parent_time: 0,
                    parent_bits: 0,
                    parent_nonce: 0
                },
                txdata,
            }
        }
        Network::Regtest => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1369199888,
                    bits: 0x1e0ffff0,
                    nonce: 12097647,
                    coinbase_txn: bitcoin_genesis_tx(),
                    block_hash: empty_block_hash,
                    coinbase_branch_hashes: vec![0; 1],
                    coinbase_branch_side_mask: 0,
                    blockchain_branch_hashes: vec![0; 1],
                    blockchain_branch_side_mask: 0,
                    parent_version: 0,
                    parent_prev_blockhash: empty_block_hash,
                    parent_merkle_root: merkle_root,
                    parent_time: 0,
                    parent_bits: 0,
                    parent_nonce: 0
                },
                txdata,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use core::default::Default;
    use hashes::hex::FromHex;

    use network::constants::Network;
    use consensus::encode::serialize;
    use blockdata::constants::{genesis_block, bitcoin_genesis_tx};
    use blockdata::constants::{MAX_SEQUENCE, COIN_VALUE};

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Default::default());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   Vec::from_hex("04ffff001d01044cd14d61792032322c20323031332c2031323a313620612e6d2e204544543a204a6170616e9273204e696b6b65692053746f636b2041766572616765204a503a4e494b202b312e3737252c20776869636820656e6465642061742074686569722068696768657374206c6576656c20696e206d6f7265207468616e206669766520796561727320696e2065616368206f6620746865206c6173742074687265652074726164696e672073657373696f6e732c20636c696d6265642061206675727468657220312e3225205765646e6573646179").unwrap());

        assert_eq!(gen.input[0].sequence, MAX_SEQUENCE);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   Vec::from_hex("41040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac").unwrap());
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, 0);

        assert_eq!(format!("{:x}", gen.wtxid()),
                   "6f80efd038566e1e3eab3e1d38131604d06481e77f2462235c6a9a94b1f8abf9".to_string());
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                   "71af8a6b906ecef9cf9cb05a593639f6bd2db7cefb9b2ceaed9065b97b01fa35".to_string());
        assert_eq!(gen.header.time, 1231006505);
        assert_eq!(gen.header.bits, 0x1d00ffff);
        assert_eq!(gen.header.nonce, 2083236893);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "64a9141746cbbe06c7e1a4b7f2abb968ccdeba66cd67c1add1091b29db00578e".to_string());
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                  "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(gen.header.bits, 0x1d00ffff);
        assert_eq!(gen.header.nonce, 414098458);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943".to_string());
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Signet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                  "6f80efd038566e1e3eab3e1d38131604d06481e77f2462235c6a9a94b1f8abf9".to_string());
        assert_eq!(gen.header.time, 1598918400);
        assert_eq!(gen.header.bits, 0x1e0377ae);
        assert_eq!(gen.header.nonce, 52613770);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "9b7bce58999062b63bfb18586813c42491fa32f4591d8d3043cb4fa9e551541b".to_string());
    }
}
