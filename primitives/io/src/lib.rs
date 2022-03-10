// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! I/O host interface for substrate runtime.
//! 用于substrate运行时的 IO 主机接口

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]
#![cfg_attr(
	feature = "std",
	doc = "Substrate runtime standard library as compiled when linked with Rust's standard library."
)]
#![cfg_attr(
	not(feature = "std"),
	doc = "Substrate's runtime standard library as compiled without Rust's standard library."
)]

use sp_std::vec::Vec;

#[cfg(feature = "std")]
use tracing;

#[cfg(feature = "std")]
use sp_core::{
	crypto::Pair,
	hexdisplay::HexDisplay,
	offchain::{OffchainDbExt, OffchainWorkerExt, TransactionPoolExt},
	storage::ChildInfo,
	traits::{RuntimeSpawnExt, TaskExecutorExt},
};
#[cfg(feature = "std")]
use sp_keystore::{KeystoreExt, SyncCryptoStore};

use sp_core::{
	crypto::KeyTypeId,
	ecdsa, ed25519,
	offchain::{
		HttpError, HttpRequestId, HttpRequestStatus, OpaqueNetworkState, StorageKind, Timestamp,
	},
	sr25519,
	storage::StateVersion,
	LogLevel, LogLevelFilter, OpaquePeerId, H256,
};

#[cfg(feature = "std")]
use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration};

use sp_runtime_interface::{
	pass_by::{PassBy, PassByCodec},
	runtime_interface, Pointer,
};

use codec::{Decode, Encode};

#[cfg(feature = "std")]
use secp256k1::{
	ecdsa::{RecoverableSignature, RecoveryId},
	Message, SECP256K1,
};

#[cfg(feature = "std")]
use sp_externalities::{Externalities, ExternalitiesExt};

#[cfg(feature = "std")]
mod batch_verifier;

#[cfg(feature = "std")]
use batch_verifier::BatchVerifier;

#[cfg(feature = "std")]
const LOG_TARGET: &str = "runtime::io";

/// Error verifying ECDSA signature
/// 验证ECDSA签名的错误类型
#[derive(Encode, Decode)]
pub enum EcdsaVerifyError {
	/// Incorrect value of R or S
	/// R或者S错误
	BadRS,
	/// Incorrect value of V
	/// 错误的V
	BadV,
	/// Invalid signature
	/// 不合法的签名
	BadSignature,
}

/// The outcome of calling `storage_kill`. Returned value is the number of storage items
/// removed from the backend from making the `storage_kill` call.
/// 调用 `storage_kill` 的结果。返回值是从后端删除的存储项目的数量，从调用 `storage_kill` 调用。
#[derive(PassByCodec, Encode, Decode)]
pub enum KillStorageResult {
	/// All key to remove were removed, return number of key removed from backend.
	/// 全部被移除，返回关键字移除的数量
	AllRemoved(u32),
	/// Not all key to remove were removed, return number of key removed from backend.
	/// 不是所有的都被移除，返回被移除的数量
	SomeRemaining(u32),
}

/// Interface for accessing the storage from within the runtime.
/// 用于从运行时访问存储的接口。
#[runtime_interface]
pub trait Storage {
	/// Returns the data for `key` in the storage or `None` if the key can not be found.
	/// 如果找到"key"，则返回存储中“key”的数据或“None”。
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		self.storage(key).map(|s| s.to_vec())
	}

	/// Get `key` from storage, placing the value into `value_out` and return the number of
	/// bytes that the entry in storage has beyond the offset or `None` if the storage entry
	/// doesn't exist at all.
	/// If `value_out` length is smaller than the returned length, only `value_out` length bytes
	/// are copied into `value_out`.
	/// 从存储中获取 `key`，将值放入 `value_out` 并返回存储中的条目超出偏移量的字节数，如果存储条目根本不存在，则返回 `None`。
	/// 如果 `value_out` 长度小于返回的长度，则只有 `value_out` 长度字节被复制到 `value_out` 中。
	fn read(&self, key: &[u8], value_out: &mut [u8], value_offset: u32) -> Option<u32> {
		self.storage(key).map(|value| {
			let value_offset = value_offset as usize;
			let data = &value[value_offset.min(value.len())..];
			let written = std::cmp::min(data.len(), value_out.len());
			value_out[..written].copy_from_slice(&data[..written]);
			data.len() as u32
		})
	}

	/// Set `key` to `value` in the storage.
	fn set(&mut self, key: &[u8], value: &[u8]) {
		self.set_storage(key.to_vec(), value.to_vec());
	}

	/// Clear the storage of the given `key` and its value.
	fn clear(&mut self, key: &[u8]) {
		self.clear_storage(key)
	}

	/// Check whether the given `key` exists in storage.
	fn exists(&self, key: &[u8]) -> bool {
		self.exists_storage(key)
	}

	/// Clear the storage of each key-value pair where the key starts with the given `prefix`.
	/// 清除以给定“前缀”开头的每个键值对的存储。
	fn clear_prefix(&mut self, prefix: &[u8]) {
		let _ = Externalities::clear_prefix(*self, prefix, None);
	}

	/// clear the storage of each key-value pair where the key starts with the given `prefix`.
	/// 清除以给定“前缀”开头的每个键值对的存储。
	/// # Limit
	///
	/// Deletes all keys from the overlay and up to `limit` keys from the backend if
	/// it is set to `Some`. No limit is applied when `limit` is set to `None`.
	/// 如果设置为 `Some`，则从覆盖层中删除所有键，并从后端删除最多 `limit` 个键。当 `limit` 设置为 `None` 时，不应用任何限制。
	/// The limit can be used to partially delete a prefix storage in case it is too large
	/// to delete in one go (block).
	/// 该限制可用于部分删除前缀存储，以防它太大而无法一次性删除（块）。
	/// It returns a boolean false iff some keys are remaining in
	/// the prefix after the functions returns. Also returns a `u32` with
	/// the number of keys removed from the process.
	/// 如果函数返回后某些键保留在前缀中，则返回布尔值 false。还返回一个“u32”，其中包含从进程中删除的键数。
	/// # Note
	///
	/// Please note that keys that are residing in the overlay for that prefix when
	/// issuing this call are all deleted without counting towards the `limit`. Only keys
	/// written during the current block are part of the overlay. Deleting with a `limit`
	/// mostly makes sense with an empty overlay for that prefix.
	/// 请注意，在发出此调用时，位于该前缀覆盖层中的键全部被删除，不计入“限制”。
	/// 只有在当前块期间写入的键是覆盖的一部分。使用 `limit` 删除对于该前缀的空覆盖大多是有意义的。
	/// Calling this function multiple times per block for the same `prefix` does
	/// not make much sense because it is not cumulative when called inside the same block.
	/// Use this function to distribute the deletion of a single child trie across multiple
	/// blocks.
	/// 为同一个“前缀”在每个块中多次调用此函数没有多大意义，因为在同一个块内调用时它不是累积的。
	/// 使用此函数将单个子 trie 的删除分布到多个块中。
	#[version(2)]
	fn clear_prefix(&mut self, prefix: &[u8], limit: Option<u32>) -> KillStorageResult {
		let (all_removed, num_removed) = Externalities::clear_prefix(*self, prefix, limit);
		match all_removed {
			true => KillStorageResult::AllRemoved(num_removed),
			false => KillStorageResult::SomeRemaining(num_removed),
		}
	}

	/// Append the encoded `value` to the storage item at `key`.
	/// 将编码的 `value` 附加到 `key` 处的存储项。
	/// The storage item needs to implement [`EncodeAppend`](codec::EncodeAppend).
	/// 存储项需要实现[`EncodeAppend`](codec::EncodeAppend)。
	/// # Warning
	///
	/// If the storage item does not support [`EncodeAppend`](codec::EncodeAppend) or
	/// something else fails at appending, the storage item will be set to `[value]`.
	/// 如果存储项不支持 [`EncodeAppend`](codec::EncodeAppend) 或其他附加失败，则存储项将设置为 `[value]`。
	fn append(&mut self, key: &[u8], value: Vec<u8>) {
		self.storage_append(key.to_vec(), value);
	}

	/// "Commit" all existing operations and compute the resulting storage root.
	/// “提交”所有现有操作并计算生成的存储根。
	/// The hashing algorithm is defined by the `Block`.
	/// 哈希算法由“块”定义。
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	/// 返回保存 SCALE 编码哈希的 `Vec<u8>`。
	fn root(&mut self) -> Vec<u8> {
		self.storage_root(StateVersion::V0)
	}

	/// "commit" all existing operations and compute the resulting storage root.
	/// “commit”所有现有操作并计算生成的存储根。
	/// The hashing algorithm is defined by the `Block`.
	/// 哈希算法由“块”定义。
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	/// 返回保存 SCALE 编码哈希的 `Vec<u8>`。
	#[version(2)]
	fn root(&mut self, version: StateVersion) -> Vec<u8> {
		self.storage_root(version)
	}

	/// Always returns `None`. This function exists for compatibility reasons.
	/// 始终返回“无”。出于兼容性原因，存在此功能。
	fn changes_root(&mut self, _parent_hash: &[u8]) -> Option<Vec<u8>> {
		None
	}

	/// Get the next key in storage after the given one in lexicographic order.
	/// 按字典顺序获取给定键之后的下一个存储键。
	fn next_key(&mut self, key: &[u8]) -> Option<Vec<u8>> {
		self.next_storage_key(&key)
	}

	/// Start a new nested transaction.
	/// 开始一个新的嵌套事务。
	/// This allows to either commit or roll back all changes that are made after this call.
	/// For every transaction there must be a matching call to either `rollback_transaction`
	/// or `commit_transaction`. This is also effective for all values manipulated using the
	/// `DefaultChildStorage` API.
	/// 这允许提交或回滚在此调用之后所做的所有更改。对于每个事务，必须有一个匹配的调用“rollback_transaction”
	/// 或“commit_transaction”。这对于使用 `DefaultChildStorage` API 操作的所有值也有效。
	/// # Warning
	///
	/// This is a low level API that is potentially dangerous as it can easily result
	/// in unbalanced transactions. For example, FRAME users should use high level storage
	/// abstractions.
	/// 这是一个具有潜在危险的低级 API，因为它很容易导致交易不平衡。例如，FRAME 用户应该使用高级存储抽象。
	fn start_transaction(&mut self) {
		self.storage_start_transaction();
	}

	/// Rollback the last transaction started by `start_transaction`.
	/// 回滚由 `start_transaction` 启动的最后一个事务。
	/// Any changes made during that transaction are discarded.
	/// 在该事务期间所做的任何更改都将被丢弃
	/// # Panics
	///
	/// Will panic if there is no open transaction.
	/// 如果没有打开的交易会恐慌。
	fn rollback_transaction(&mut self) {
		self.storage_rollback_transaction()
			.expect("No open transaction that can be rolled back.");
	}

	/// Commit the last transaction started by `start_transaction`.
	/// 提交由 `start_transaction` 启动的最后一个事务。
	/// Any changes made during that transaction are committed.
	/// 在该事务期间所做的任何更改都将被提交。
	/// # Panics
	///
	/// Will panic if there is no open transaction.
	/// 如果没有打开的交易会恐慌。
	fn commit_transaction(&mut self) {
		self.storage_commit_transaction()
			.expect("No open transaction that can be committed.");
	}
}

/// Interface for accessing the child storage for default child trie,
/// from within the runtime.
/// 用于从运行时访问默认子 trie 的子存储的接口。
#[runtime_interface]
pub trait DefaultChildStorage {
	/// Get a default child storage value for a given key.
	/// 获取给定键的默认子存储值
	/// Parameter `storage_key` is the unprefixed location of the root of the child trie in the
	/// parent trie. Result is `None` if the value for `key` in the child storage can not be found.
	/// 参数 `storage_key` 是父 trie 中子 trie 的根的无前缀位置。如果在子存储中找不到 `key` 的值，则结果为 `None`。
	fn get(&self, storage_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage(&child_info, key).map(|s| s.to_vec())
	}

	/// Allocation efficient variant of `get`.
	/// `get` 的分配高效变体。
	/// Get `key` from child storage, placing the value into `value_out` and return the number
	/// of bytes that the entry in storage has beyond the offset or `None` if the storage entry
	/// doesn't exist at all.
	/// If `value_out` length is smaller than the returned length, only `value_out` length bytes
	/// are copied into `value_out`.
	/// 从子存储中获取 `key`，将值放入 `value_out` 并返回存储中的条目超出偏移量的字节数，如果存储条目根本不存在，则返回 `None`。
	/// 如果 `value_out` 长度小于返回的长度，则只有 `value_out` 长度字节被复制到 `value_out` 中。
	fn read(
		&self,
		storage_key: &[u8],
		key: &[u8],
		value_out: &mut [u8],
		value_offset: u32,
	) -> Option<u32> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage(&child_info, key).map(|value| {
			let value_offset = value_offset as usize;
			let data = &value[value_offset.min(value.len())..];
			let written = std::cmp::min(data.len(), value_out.len());
			value_out[..written].copy_from_slice(&data[..written]);
			data.len() as u32
		})
	}

	/// Set a child storage value.
	/// 设置子存储值
	/// Set `key` to `value` in the child storage denoted by `storage_key`.
	/// 在由 `storage_key` 表示的子存储中将 `key` 设置为 `value`。
	fn set(&mut self, storage_key: &[u8], key: &[u8], value: &[u8]) {
		let child_info = ChildInfo::new_default(storage_key);
		self.set_child_storage(&child_info, key.to_vec(), value.to_vec());
	}

	/// Clear a child storage key.
	/// 清除子存储密钥
	/// For the default child storage at `storage_key`, clear value at `key`.
	fn clear(&mut self, storage_key: &[u8], key: &[u8]) {
		let child_info = ChildInfo::new_default(storage_key);
		self.clear_child_storage(&child_info, key);
	}

	/// Clear an entire child storage.
	/// 清除整个子存储。
	/// If it exists, the child storage for `storage_key`
	/// is removed.
	fn storage_kill(&mut self, storage_key: &[u8]) {
		let child_info = ChildInfo::new_default(storage_key);
		self.kill_child_storage(&child_info, None);
	}

	/// Clear a child storage key.
	///
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(2)]
	fn storage_kill(&mut self, storage_key: &[u8], limit: Option<u32>) -> bool {
		let child_info = ChildInfo::new_default(storage_key);
		let (all_removed, _num_removed) = self.kill_child_storage(&child_info, limit);
		all_removed
	}

	/// Clear a child storage key.
	///
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(3)]
	fn storage_kill(&mut self, storage_key: &[u8], limit: Option<u32>) -> KillStorageResult {
		let child_info = ChildInfo::new_default(storage_key);
		let (all_removed, num_removed) = self.kill_child_storage(&child_info, limit);
		match all_removed {
			true => KillStorageResult::AllRemoved(num_removed),
			false => KillStorageResult::SomeRemaining(num_removed),
		}
	}

	/// Check a child storage key.
	/// 判断存在与否
	/// Check whether the given `key` exists in default child defined at `storage_key`.
	fn exists(&self, storage_key: &[u8], key: &[u8]) -> bool {
		let child_info = ChildInfo::new_default(storage_key);
		self.exists_child_storage(&child_info, key)
	}

	/// Clear child default key by prefix.
	/// 按前缀清除子默认键
	/// Clear the child storage of each key-value pair where the key starts with the given `prefix`.
	fn clear_prefix(&mut self, storage_key: &[u8], prefix: &[u8]) {
		let child_info = ChildInfo::new_default(storage_key);
		let _ = self.clear_child_prefix(&child_info, prefix, None);
	}

	/// Clear the child storage of each key-value pair where the key starts with the given `prefix`.
	/// 清除每个键值对的子存储，其中键以给定的“前缀”开头。
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(2)]
	fn clear_prefix(
		&mut self,
		storage_key: &[u8],
		prefix: &[u8],
		limit: Option<u32>,
	) -> KillStorageResult {
		let child_info = ChildInfo::new_default(storage_key);
		let (all_removed, num_removed) = self.clear_child_prefix(&child_info, prefix, limit);
		match all_removed {
			true => KillStorageResult::AllRemoved(num_removed),
			false => KillStorageResult::SomeRemaining(num_removed),
		}
	}

	/// Default child root calculation.
	/// 默认子根计算
	/// "Commit" all existing operations and compute the resulting child storage root.
	/// The hashing algorithm is defined by the `Block`.
	/// 提交”所有现有操作并计算生成的子存储根。哈希算法由“块”定义。
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	/// 返回保存 SCALE 编码哈希的 `Vec<u8>`。
	fn root(&mut self, storage_key: &[u8]) -> Vec<u8> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage_root(&child_info, StateVersion::V0)
	}

	/// Default child root calculation.
	/// 默认子根计算
	/// "Commit" all existing operations and compute the resulting child storage root.
	/// The hashing algorithm is defined by the `Block`.
	/// “Commit”所有现有操作并计算生成的子存储根。哈希算法由“Block”定义。
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	/// 返回保存 SCALE 编码哈希的 `Vec<u8>`。
	#[version(2)]
	fn root(&mut self, storage_key: &[u8], version: StateVersion) -> Vec<u8> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage_root(&child_info, version)
	}

	/// Child storage key iteration.
	/// 子存储键迭代。
	/// Get the next key in storage after the given one in lexicographic order in child storage.
	/// 在子存储中按字典顺序获取给定键之后的下一个存储键。
	fn next_key(&mut self, storage_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
		let child_info = ChildInfo::new_default(storage_key);
		self.next_child_storage_key(&child_info, key)
	}
}

/// Interface that provides trie related functionality.
/// 提供 trie 相关功能的接口。
#[runtime_interface]
pub trait Trie {
	/// A trie root formed from the iterated items.
	/// 由迭代项形成的 trie 根。
	fn blake2_256_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
		LayoutV0::<sp_core::Blake2Hasher>::trie_root(input)
	}

	/// A trie root formed from the iterated items.
	/// 由迭代项形成的 trie 根。
	#[version(2)]
	fn blake2_256_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> H256 {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::Blake2Hasher>::trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::Blake2Hasher>::trie_root(input),
		}
	}

	/// A trie root formed from the enumerated items.
	/// 由枚举项形成的 trie 根。
	fn blake2_256_ordered_root(input: Vec<Vec<u8>>) -> H256 {
		LayoutV0::<sp_core::Blake2Hasher>::ordered_trie_root(input)
	}

	/// A trie root formed from the enumerated items.
	/// 由枚举项形成的 trie 根。
	#[version(2)]
	fn blake2_256_ordered_root(input: Vec<Vec<u8>>, version: StateVersion) -> H256 {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::Blake2Hasher>::ordered_trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::Blake2Hasher>::ordered_trie_root(input),
		}
	}

	/// A trie root formed from the iterated items.
	/// 由迭代项形成的 trie 根。
	fn keccak_256_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
		LayoutV0::<sp_core::KeccakHasher>::trie_root(input)
	}

	/// A trie root formed from the iterated items.
	/// 由迭代项形成的 trie 根。
	#[version(2)]
	fn keccak_256_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> H256 {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::KeccakHasher>::trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::KeccakHasher>::trie_root(input),
		}
	}

	/// A trie root formed from the enumerated items.
	/// 由枚举项形成的 trie 根。
	fn keccak_256_ordered_root(input: Vec<Vec<u8>>) -> H256 {
		LayoutV0::<sp_core::KeccakHasher>::ordered_trie_root(input)
	}

	/// A trie root formed from the enumerated items.
	/// 由枚举项组成的 trie 根。
	#[version(2)]
	fn keccak_256_ordered_root(input: Vec<Vec<u8>>, version: StateVersion) -> H256 {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::KeccakHasher>::ordered_trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::KeccakHasher>::ordered_trie_root(input),
		}
	}

	/// Verify trie proof
	/// 验证trie证明
	fn blake2_256_verify_proof(root: H256, proof: &[Vec<u8>], key: &[u8], value: &[u8]) -> bool {
		sp_trie::verify_trie_proof::<LayoutV0<sp_core::Blake2Hasher>, _, _, _>(
			&root,
			proof,
			&[(key, Some(value))],
		)
		.is_ok()
	}

	/// Verify trie proof
	#[version(2)]
	fn blake2_256_verify_proof(
		root: H256,
		proof: &[Vec<u8>],
		key: &[u8],
		value: &[u8],
		version: StateVersion,
	) -> bool {
		match version {
			StateVersion::V0 => sp_trie::verify_trie_proof::<
				LayoutV0<sp_core::Blake2Hasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
			StateVersion::V1 => sp_trie::verify_trie_proof::<
				LayoutV1<sp_core::Blake2Hasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
		}
	}

	/// Verify trie proof
	fn keccak_256_verify_proof(root: H256, proof: &[Vec<u8>], key: &[u8], value: &[u8]) -> bool {
		sp_trie::verify_trie_proof::<LayoutV0<sp_core::KeccakHasher>, _, _, _>(
			&root,
			proof,
			&[(key, Some(value))],
		)
		.is_ok()
	}

	/// Verify trie proof
	#[version(2)]
	fn keccak_256_verify_proof(
		root: H256,
		proof: &[Vec<u8>],
		key: &[u8],
		value: &[u8],
		version: StateVersion,
	) -> bool {
		match version {
			StateVersion::V0 => sp_trie::verify_trie_proof::<
				LayoutV0<sp_core::KeccakHasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
			StateVersion::V1 => sp_trie::verify_trie_proof::<
				LayoutV1<sp_core::KeccakHasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
		}
	}
}

/// Interface that provides miscellaneous functions for communicating between the runtime and the
/// node.
/// 为运行时和节点之间的通信提供各种功能的接口。
#[runtime_interface]
pub trait Misc {
	// NOTE: We use the target 'runtime' for messages produced by general printing functions,
	// instead of LOG_TARGET.

	/// Print a number.
	fn print_num(val: u64) {
		log::debug!(target: "runtime", "{}", val);
	}

	/// Print any valid `utf8` buffer.
	fn print_utf8(utf8: &[u8]) {
		if let Ok(data) = std::str::from_utf8(utf8) {
			log::debug!(target: "runtime", "{}", data)
		}
	}

	/// Print any `u8` slice as hex.
	fn print_hex(data: &[u8]) {
		log::debug!(target: "runtime", "{}", HexDisplay::from(&data));
	}

	/// Extract the runtime version of the given wasm blob by calling `Core_version`.
	/// 通过调用 `Core_version` 提取给定 wasm blob 的运行时版本。
	/// Returns `None` if calling the function failed for any reason or `Some(Vec<u8>)` where
	/// the `Vec<u8>` holds the SCALE encoded runtime version.
	///
	/// # Performance
	///
	/// This function may be very expensive to call depending on the wasm binary. It may be
	/// relatively cheap if the wasm binary contains version information. In that case,
	/// uncompression of the wasm blob is the dominating factor.
	///
	/// If the wasm binary does not have the version information attached, then a legacy mechanism
	/// may be involved. This means that a runtime call will be performed to query the version.
	///
	/// Calling into the runtime may be incredible expensive and should be approached with care.
	fn runtime_version(&mut self, wasm: &[u8]) -> Option<Vec<u8>> {
		use sp_core::traits::ReadRuntimeVersionExt;

		let mut ext = sp_state_machine::BasicExternalities::default();

		match self
			.extension::<ReadRuntimeVersionExt>()
			.expect("No `ReadRuntimeVersionExt` associated for the current context!")
			.read_runtime_version(wasm, &mut ext)
		{
			Ok(v) => Some(v),
			Err(err) => {
				log::debug!(
					target: LOG_TARGET,
					"cannot read version from the given runtime: {}",
					err,
				);
				None
			},
		}
	}
}

/// Interfaces for working with crypto related types from within the runtime.
/// 用于在运行时中处理加密相关类型的接口
#[runtime_interface]
pub trait Crypto {
	/// Returns all `ed25519` public keys for the given key id from the keystore.
	/// 从密钥库中返回给定密钥 id 的所有 `ed25519` 公钥。
	fn ed25519_public_keys(&mut self, id: KeyTypeId) -> Vec<ed25519::Public> {
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::ed25519_public_keys(keystore, id)
	}

	/// Generate an `ed22519` key for the given key type using an optional `seed` and
	/// store it in the keystore.
	/// 使用可选的“种子”为给定的密钥类型生成一个“ed22519”密钥并将其存储在密钥库中。
	/// The `seed` needs to be a valid utf8.
	/// 种子必须是一个合法得utf8格式
	/// Returns the public key.
	/// 返回公钥
	fn ed25519_generate(&mut self, id: KeyTypeId, seed: Option<Vec<u8>>) -> ed25519::Public {
		let seed = seed.as_ref().map(|s| std::str::from_utf8(&s).expect("Seed is valid utf8!"));
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::ed25519_generate_new(keystore, id, seed)
			.expect("`ed25519_generate` failed")
	}

	/// Sign the given `msg` with the `ed25519` key that corresponds to the given public key and
	/// key type in the keystore.
	/// 使用与密钥库中给定公钥和密钥类型相对应的 `ed25519` 密钥对给定的 `msg` 签名。
	/// Returns the signature.
	/// 返回签名
	fn ed25519_sign(
		&mut self,
		id: KeyTypeId,
		pub_key: &ed25519::Public,
		msg: &[u8],
	) -> Option<ed25519::Signature> {
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::sign_with(keystore, id, &pub_key.into(), msg)
			.ok()
			.flatten()
			.and_then(|sig| ed25519::Signature::from_slice(&sig))
	}

	/// Verify `ed25519` signature.
	/// 验证“ed25519”签名。
	/// returns `true` when the verification was successful.
	/// 验证成功时返回 `true`。
	fn ed25519_verify(sig: &ed25519::Signature, msg: &[u8], pub_key: &ed25519::Public) -> bool {
		ed25519::Pair::verify(sig, msg, pub_key)
	}

	/// Register a `ed25519` signature for batch verification.
	/// 注册一个 `ed25519` 签名以进行批量验证。
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediatley.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	/// 必须通过调用 [`start_batch_verify`] 来启用批量验证。
	/// 如果未启用批量验证，则将立即验证签名。要获得批量验证的结果，需要调用 [`finish_batch_verify`]。
	/// Returns `true` when the verification is either successful or batched.
	/// 当验证成功或批处理时返回 `true`。
	fn ed25519_batch_verify(
		&mut self,
		sig: &ed25519::Signature,
		msg: &[u8],
		pub_key: &ed25519::Public,
	) -> bool {
		self.extension::<VerificationExt>()
			.map(|extension| extension.push_ed25519(sig.clone(), pub_key.clone(), msg.to_vec()))
			.unwrap_or_else(|| ed25519_verify(sig, msg, pub_key))
	}

	/// Verify `sr25519` signature.
	/// 验证`sr25519`签名
	/// Returns `true` when the verification was successful.
	#[version(2)]
	fn sr25519_verify(sig: &sr25519::Signature, msg: &[u8], pub_key: &sr25519::Public) -> bool {
		sr25519::Pair::verify(sig, msg, pub_key)
	}

	/// Register a `sr25519` signature for batch verification.
	/// 批量验证`sr25519`签名
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediatley.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	///
	/// Returns `true` when the verification is either successful or batched.
	fn sr25519_batch_verify(
		&mut self,
		sig: &sr25519::Signature,
		msg: &[u8],
		pub_key: &sr25519::Public,
	) -> bool {
		self.extension::<VerificationExt>()
			.map(|extension| extension.push_sr25519(sig.clone(), pub_key.clone(), msg.to_vec()))
			.unwrap_or_else(|| sr25519_verify(sig, msg, pub_key))
	}

	/// Start verification extension.
	/// 启动验证扩展
	fn start_batch_verify(&mut self) {
		let scheduler = self
			.extension::<TaskExecutorExt>()
			.expect("No task executor associated with the current context!")
			.clone();

		self.register_extension(VerificationExt(BatchVerifier::new(scheduler)))
			.expect("Failed to register required extension: `VerificationExt`");
	}

	/// Finish batch-verification of signatures.
	/// 完成签名的批量验证
	/// Verify or wait for verification to finish for all signatures which were previously
	/// deferred by `sr25519_verify`/`ed25519_verify`.
	/// 验证或等待验证完成之前由 sr25519_verify/ed25519_verify 延迟的所有签名。
	/// Will panic if no `VerificationExt` is registered (`start_batch_verify` was not called).
	/// 如果没有注册 `VerificationExt` 会出现恐慌（`start_batch_verify` 没有被调用）。
	fn finish_batch_verify(&mut self) -> bool {
		let result = self
			.extension::<VerificationExt>()
			.expect("`finish_batch_verify` should only be called after `start_batch_verify`")
			.verify_and_clear();

		self.deregister_extension::<VerificationExt>()
			.expect("No verification extension in current context!");

		result
	}

	/// Returns all `sr25519` public keys for the given key id from the keystore.
	/// 从密钥库中返回给定密钥 id 的所有 `sr25519` 公钥。
	fn sr25519_public_keys(&mut self, id: KeyTypeId) -> Vec<sr25519::Public> {
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::sr25519_public_keys(keystore, id)
	}

	/// Generate an `sr22519` key for the given key type using an optional seed and
	/// store it in the keystore.
	/// 使用可选种子为给定密钥类型生成“sr22519”密钥并将其存储在密钥库中。
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	fn sr25519_generate(&mut self, id: KeyTypeId, seed: Option<Vec<u8>>) -> sr25519::Public {
		let seed = seed.as_ref().map(|s| std::str::from_utf8(&s).expect("Seed is valid utf8!"));
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::sr25519_generate_new(keystore, id, seed)
			.expect("`sr25519_generate` failed")
	}

	/// Sign the given `msg` with the `sr25519` key that corresponds to the given public key and
	/// key type in the keystore.
	/// 使用与密钥库中给定的公钥和密钥类型对应的 sr25519 密钥对给定的 msg 进行签名。
	/// Returns the signature.
	fn sr25519_sign(
		&mut self,
		id: KeyTypeId,
		pub_key: &sr25519::Public,
		msg: &[u8],
	) -> Option<sr25519::Signature> {
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::sign_with(keystore, id, &pub_key.into(), msg)
			.ok()
			.flatten()
			.and_then(|sig| sr25519::Signature::from_slice(&sig))
	}

	/// Verify an `sr25519` signature.
	/// 验证`sr25519`签名
	/// Returns `true` when the verification in successful regardless of
	/// signature version.
	fn sr25519_verify(sig: &sr25519::Signature, msg: &[u8], pubkey: &sr25519::Public) -> bool {
		sr25519::Pair::verify_deprecated(sig, msg, pubkey)
	}

	/// Returns all `ecdsa` public keys for the given key id from the keystore.
	/// 从密钥库中返回给定密钥 ID 的所有“ecdsa”公钥。
	fn ecdsa_public_keys(&mut self, id: KeyTypeId) -> Vec<ecdsa::Public> {
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::ecdsa_public_keys(keystore, id)
	}

	/// Generate an `ecdsa` key for the given key type using an optional `seed` and
	/// store it in the keystore.
	/// 使用可选的“种子”为给定的密钥类型生成一个“ecdsa”密钥，并将其存储在密钥库中。
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	fn ecdsa_generate(&mut self, id: KeyTypeId, seed: Option<Vec<u8>>) -> ecdsa::Public {
		let seed = seed.as_ref().map(|s| std::str::from_utf8(&s).expect("Seed is valid utf8!"));
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::ecdsa_generate_new(keystore, id, seed).expect("`ecdsa_generate` failed")
	}

	/// Sign the given `msg` with the `ecdsa` key that corresponds to the given public key and
	/// key type in the keystore.
	/// 使用与密钥库中给定的公钥和密钥类型相对应的 ecdsa 密钥对给定的 msg 进行签名。
	/// Returns the signature.
	fn ecdsa_sign(
		&mut self,
		id: KeyTypeId,
		pub_key: &ecdsa::Public,
		msg: &[u8],
	) -> Option<ecdsa::Signature> {
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::sign_with(keystore, id, &pub_key.into(), msg)
			.ok()
			.flatten()
			.and_then(|sig| ecdsa::Signature::from_slice(&sig))
	}

	/// Sign the given a pre-hashed `msg` with the `ecdsa` key that corresponds to the given public
	/// key and key type in the keystore.
	/// 使用与密钥库中给定的公钥和密钥类型相对应的 ecdsa 密钥对给定的预散列的 msg 进行签名。
	/// Returns the signature.
	fn ecdsa_sign_prehashed(
		&mut self,
		id: KeyTypeId,
		pub_key: &ecdsa::Public,
		msg: &[u8; 32],
	) -> Option<ecdsa::Signature> {
		let keystore = &***self
			.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!");
		SyncCryptoStore::ecdsa_sign_prehashed(keystore, id, pub_key, msg).ok().flatten()
	}

	/// Verify `ecdsa` signature.
	///
	/// Returns `true` when the verification was successful.
	/// This version is able to handle, non-standard, overflowing signatures.
	fn ecdsa_verify(sig: &ecdsa::Signature, msg: &[u8], pub_key: &ecdsa::Public) -> bool {
		#[allow(deprecated)]
		ecdsa::Pair::verify_deprecated(sig, msg, pub_key)
	}

	/// Verify `ecdsa` signature.
	///
	/// Returns `true` when the verification was successful.
	#[version(2)]
	fn ecdsa_verify(sig: &ecdsa::Signature, msg: &[u8], pub_key: &ecdsa::Public) -> bool {
		ecdsa::Pair::verify(sig, msg, pub_key)
	}

	/// Verify `ecdsa` signature with pre-hashed `msg`.
	/// 使用预先散列的 `msg` 验证 `ecdsa` 签名。
	/// Returns `true` when the verification was successful.
	fn ecdsa_verify_prehashed(
		sig: &ecdsa::Signature,
		msg: &[u8; 32],
		pub_key: &ecdsa::Public,
	) -> bool {
		ecdsa::Pair::verify_prehashed(sig, msg, pub_key)
	}

	/// Register a `ecdsa` signature for batch verification.
	/// 注册一个 `ecdsa` 签名以进行批量验证。
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediatley.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	///
	/// Returns `true` when the verification is either successful or batched.
	fn ecdsa_batch_verify(
		&mut self,
		sig: &ecdsa::Signature,
		msg: &[u8],
		pub_key: &ecdsa::Public,
	) -> bool {
		self.extension::<VerificationExt>()
			.map(|extension| extension.push_ecdsa(sig.clone(), pub_key.clone(), msg.to_vec()))
			.unwrap_or_else(|| ecdsa_verify(sig, msg, pub_key))
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	/// 验证并恢复 SECP256k1 ECDSA 签名。
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	/// - `sig` 以 RSV 格式传递。 V 应该是“01”或“2728”。
	/// - `msg` 是消息的 blake2-256 哈希值。
	/// Returns `Err` if the signature is bad, otherwise the 64-byte pubkey
	/// (doesn't include the 0x04 prefix).
	/// This version is able to handle, non-standard, overflowing signatures.
	fn secp256k1_ecdsa_recover(
		sig: &[u8; 65],
		msg: &[u8; 32],
	) -> Result<[u8; 64], EcdsaVerifyError> {
		let rid = libsecp256k1::RecoveryId::parse(
			if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8,
		)
		.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = libsecp256k1::Signature::parse_overflowing_slice(&sig[..64])
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = libsecp256k1::Message::parse(msg);
		let pubkey =
			libsecp256k1::recover(&msg, &sig, &rid).map_err(|_| EcdsaVerifyError::BadSignature)?;
		let mut res = [0u8; 64];
		res.copy_from_slice(&pubkey.serialize()[1..65]);
		Ok(res)
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	///
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	///
	/// Returns `Err` if the signature is bad, otherwise the 64-byte pubkey
	/// (doesn't include the 0x04 prefix).
	#[version(2)]
	fn secp256k1_ecdsa_recover(
		sig: &[u8; 65],
		msg: &[u8; 32],
	) -> Result<[u8; 64], EcdsaVerifyError> {
		let rid = RecoveryId::from_i32(if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as i32)
			.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = RecoverableSignature::from_compact(&sig[..64], rid)
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = Message::from_slice(msg).expect("Message is 32 bytes; qed");
		let pubkey = SECP256K1
			.recover_ecdsa(&msg, &sig)
			.map_err(|_| EcdsaVerifyError::BadSignature)?;
		let mut res = [0u8; 64];
		res.copy_from_slice(&pubkey.serialize_uncompressed()[1..]);
		Ok(res)
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	///
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	///
	/// Returns `Err` if the signature is bad, otherwise the 33-byte compressed pubkey.
	fn secp256k1_ecdsa_recover_compressed(
		sig: &[u8; 65],
		msg: &[u8; 32],
	) -> Result<[u8; 33], EcdsaVerifyError> {
		let rid = libsecp256k1::RecoveryId::parse(
			if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8,
		)
		.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = libsecp256k1::Signature::parse_overflowing_slice(&sig[0..64])
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = libsecp256k1::Message::parse(msg);
		let pubkey =
			libsecp256k1::recover(&msg, &sig, &rid).map_err(|_| EcdsaVerifyError::BadSignature)?;
		Ok(pubkey.serialize_compressed())
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	///
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	///
	/// Returns `Err` if the signature is bad, otherwise the 33-byte compressed pubkey.
	#[version(2)]
	fn secp256k1_ecdsa_recover_compressed(
		sig: &[u8; 65],
		msg: &[u8; 32],
	) -> Result<[u8; 33], EcdsaVerifyError> {
		let rid = RecoveryId::from_i32(if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as i32)
			.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = RecoverableSignature::from_compact(&sig[..64], rid)
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = Message::from_slice(msg).expect("Message is 32 bytes; qed");
		let pubkey = SECP256K1
			.recover_ecdsa(&msg, &sig)
			.map_err(|_| EcdsaVerifyError::BadSignature)?;
		Ok(pubkey.serialize())
	}
}

/// Interface that provides functions for hashing with different algorithms.
/// 提供使用不同算法进行散列的函数的接口。
#[runtime_interface]
pub trait Hashing {
	/// Conduct a 256-bit Keccak hash.
	/// 执行 256 位 Keccak 哈希。
	fn keccak_256(data: &[u8]) -> [u8; 32] {
		sp_core::hashing::keccak_256(data)
	}

	/// Conduct a 512-bit Keccak hash.
	fn keccak_512(data: &[u8]) -> [u8; 64] {
		sp_core::hashing::keccak_512(data)
	}

	/// Conduct a 256-bit Sha2 hash.
	fn sha2_256(data: &[u8]) -> [u8; 32] {
		sp_core::hashing::sha2_256(data)
	}

	/// Conduct a 128-bit Blake2 hash.
	fn blake2_128(data: &[u8]) -> [u8; 16] {
		sp_core::hashing::blake2_128(data)
	}

	/// Conduct a 256-bit Blake2 hash.
	fn blake2_256(data: &[u8]) -> [u8; 32] {
		sp_core::hashing::blake2_256(data)
	}

	/// Conduct four XX hashes to give a 256-bit result.
	fn twox_256(data: &[u8]) -> [u8; 32] {
		sp_core::hashing::twox_256(data)
	}

	/// Conduct two XX hashes to give a 128-bit result.
	fn twox_128(data: &[u8]) -> [u8; 16] {
		sp_core::hashing::twox_128(data)
	}

	/// Conduct two XX hashes to give a 64-bit result.
	fn twox_64(data: &[u8]) -> [u8; 8] {
		sp_core::hashing::twox_64(data)
	}
}

/// Interface that provides transaction indexing API.
/// 提供事务索引 API 的接口。
#[runtime_interface]
pub trait TransactionIndex {
	/// Add transaction index. Returns indexed content hash.
	/// 添加交易索引。返回索引的内容哈希。
	fn index(&mut self, extrinsic: u32, size: u32, context_hash: [u8; 32]) {
		self.storage_index_transaction(extrinsic, &context_hash, size);
	}

	/// Conduct a 512-bit Keccak hash.
	/// 执行 512 位 Keccak 哈希。
	fn renew(&mut self, extrinsic: u32, context_hash: [u8; 32]) {
		self.storage_renew_transaction_index(extrinsic, &context_hash);
	}
}

/// Interface that provides functions to access the Offchain DB.
/// 提供访问 Offchain DB 的功能的接口。
#[runtime_interface]
pub trait OffchainIndex {
	/// Write a key value pair to the Offchain DB database in a buffered fashion.
	/// 以缓冲方式将键值对写入 Offchain DB 数据库。
	fn set(&mut self, key: &[u8], value: &[u8]) {
		self.set_offchain_storage(key, Some(value));
	}

	/// Remove a key and its associated value from the Offchain DB.
	fn clear(&mut self, key: &[u8]) {
		self.set_offchain_storage(key, None);
	}
}

#[cfg(feature = "std")]
sp_externalities::decl_extension! {
	/// Batch verification extension to register/retrieve from the externalities.
	/// 从外部性中注册检索的批量验证扩展。
	pub struct VerificationExt(BatchVerifier);
}

/// Interface that provides functions to access the offchain functionality.
/// 提供访问链下功能的功能的接口
/// These functions are being made available to the runtime and are called by the runtime.
/// 这些函数可供运行时使用并由运行时调用。
#[runtime_interface]
pub trait Offchain {
	/// Returns if the local node is a potential validator.
	/// 返回本地节点是否是潜在的验证者。
	/// Even if this function returns `true`, it does not mean that any keys are configured
	/// and that the validator is registered in the chain.
	/// 即使此函数返回 `true`，也不意味着配置了任何密钥并且验证器已在链中注册。
	fn is_validator(&mut self) -> bool {
		self.extension::<OffchainWorkerExt>()
			.expect("is_validator can be called only in the offchain worker context")
			.is_validator()
	}

	/// Submit an encoded transaction to the pool.
	/// 将编码交易提交到池中。
	/// The transaction will end up in the pool.
	/// 交易将最终进入池中。
	fn submit_transaction(&mut self, data: Vec<u8>) -> Result<(), ()> {
		self.extension::<TransactionPoolExt>()
			.expect(
				"submit_transaction can be called only in the offchain call context with
				TransactionPool capabilities enabled",
			)
			.submit_transaction(data)
	}

	/// Returns information about the local node's network state.
	/// 返回有关本地节点网络状态的信息。
	fn network_state(&mut self) -> Result<OpaqueNetworkState, ()> {
		self.extension::<OffchainWorkerExt>()
			.expect("network_state can be called only in the offchain worker context")
			.network_state()
	}

	/// Returns current UNIX timestamp (in millis)
	/// 返回当前unix时间戳
	fn timestamp(&mut self) -> Timestamp {
		self.extension::<OffchainWorkerExt>()
			.expect("timestamp can be called only in the offchain worker context")
			.timestamp()
	}

	/// Pause the execution until `deadline` is reached.
	/// 暂停执行，直到达到 `deadline`。
	fn sleep_until(&mut self, deadline: Timestamp) {
		self.extension::<OffchainWorkerExt>()
			.expect("sleep_until can be called only in the offchain worker context")
			.sleep_until(deadline)
	}

	/// Returns a random seed.
	/// 返回一个随机种子。
	/// This is a truly random, non-deterministic seed generated by host environment.
	/// Obviously fine in the off-chain worker context.
	/// 这是由宿主环境生成的真正随机的、非确定性的种子。在链下工作者环境中显然很好。
	fn random_seed(&mut self) -> [u8; 32] {
		self.extension::<OffchainWorkerExt>()
			.expect("random_seed can be called only in the offchain worker context")
			.random_seed()
	}

	/// Sets a value in the local storage.
	/// 在本地存储中设置一个值。
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	/// 请注意，此存储不是共识的一部分，它只能由在同一台机器上运行的脱链工作任务访问。它在运行之间持续存在。
	fn local_storage_set(&mut self, kind: StorageKind, key: &[u8], value: &[u8]) {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_set can be called only in the offchain call context with
				OffchainDb extension",
			)
			.local_storage_set(kind, key, value)
	}

	/// Remove a value from the local storage.
	/// 从本地存储中删除一个值。
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	fn local_storage_clear(&mut self, kind: StorageKind, key: &[u8]) {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_clear can be called only in the offchain call context with
				OffchainDb extension",
			)
			.local_storage_clear(kind, key)
	}

	/// Sets a value in the local storage if it matches current value.
	/// 如果与当前值匹配，则在本地存储中设置一个值。
	/// Since multiple offchain workers may be running concurrently, to prevent
	/// data races use CAS to coordinate between them.
	/// 由于多个链下工作人员可能同时运行，为了防止数据竞争，使用 CAS 在它们之间进行协调。
	/// Returns `true` if the value has been set, `false` otherwise.
	///
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	fn local_storage_compare_and_set(
		&mut self,
		kind: StorageKind,
		key: &[u8],
		old_value: Option<Vec<u8>>,
		new_value: &[u8],
	) -> bool {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_compare_and_set can be called only in the offchain call context
				with OffchainDb extension",
			)
			.local_storage_compare_and_set(kind, key, old_value.as_deref(), new_value)
	}

	/// Gets a value from the local storage.
	/// 从本地存储中获取一个值。
	/// If the value does not exist in the storage `None` will be returned.
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	fn local_storage_get(&mut self, kind: StorageKind, key: &[u8]) -> Option<Vec<u8>> {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_get can be called only in the offchain call context with
				OffchainDb extension",
			)
			.local_storage_get(kind, key)
	}

	/// Initiates a http request given HTTP verb and the URL.
	/// 在给定 HTTP 动词和 URL 的情况下发起一个 http 请求。
	/// Meta is a future-reserved field containing additional, parity-scale-codec encoded
	/// parameters. Returns the id of newly started request.
	fn http_request_start(
		&mut self,
		method: &str,
		uri: &str,
		meta: &[u8],
	) -> Result<HttpRequestId, ()> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_start can be called only in the offchain worker context")
			.http_request_start(method, uri, meta)
	}

	/// Append header to the request.
	fn http_request_add_header(
		&mut self,
		request_id: HttpRequestId,
		name: &str,
		value: &str,
	) -> Result<(), ()> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_add_header can be called only in the offchain worker context")
			.http_request_add_header(request_id, name, value)
	}

	/// Write a chunk of request body.
	/// 写一大块请求正文。
	/// Writing an empty chunks finalizes the request.
	/// Passing `None` as deadline blocks forever.
	/// 写一个空的块来完成请求。将“None”作为截止日期永远阻塞。
	/// Returns an error in case deadline is reached or the chunk couldn't be written.
	/// 如果达到最后期限或无法写入块，则返回错误。
	fn http_request_write_body(
		&mut self,
		request_id: HttpRequestId,
		chunk: &[u8],
		deadline: Option<Timestamp>,
	) -> Result<(), HttpError> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_write_body can be called only in the offchain worker context")
			.http_request_write_body(request_id, chunk, deadline)
	}

	/// Block and wait for the responses for given requests.
	/// 阻止并等待给定请求的响应。
	/// Returns a vector of request statuses (the len is the same as ids).
	/// Note that if deadline is not provided the method will block indefinitely,
	/// otherwise unready responses will produce `DeadlineReached` status.
	///
	/// Passing `None` as deadline blocks forever.
	fn http_response_wait(
		&mut self,
		ids: &[HttpRequestId],
		deadline: Option<Timestamp>,
	) -> Vec<HttpRequestStatus> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_response_wait can be called only in the offchain worker context")
			.http_response_wait(ids, deadline)
	}

	/// Read all response headers.
	/// 读取所有响应标头
	/// Returns a vector of pairs `(HeaderKey, HeaderValue)`.
	/// NOTE response headers have to be read before response body.
	fn http_response_headers(&mut self, request_id: HttpRequestId) -> Vec<(Vec<u8>, Vec<u8>)> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_response_headers can be called only in the offchain worker context")
			.http_response_headers(request_id)
	}

	/// Read a chunk of body response to given buffer.
	/// 读取给定缓冲区的主体响应块。
	/// Returns the number of bytes written or an error in case a deadline
	/// is reached or server closed the connection.
	/// If `0` is returned it means that the response has been fully consumed
	/// and the `request_id` is now invalid.
	/// NOTE this implies that response headers must be read before draining the body.
	/// Passing `None` as a deadline blocks forever.
	/// 如果达到最后期限或服务器关闭连接，则返回写入的字节数或错误。
	/// 如果返回“0”，则表示响应已被完全消耗，“request_id”现在无效。
	/// 注意这意味着必须在耗尽正文之前读取响应标头
	fn http_response_read_body(
		&mut self,
		request_id: HttpRequestId,
		buffer: &mut [u8],
		deadline: Option<Timestamp>,
	) -> Result<u32, HttpError> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_response_read_body can be called only in the offchain worker context")
			.http_response_read_body(request_id, buffer, deadline)
			.map(|r| r as u32)
	}

	/// Set the authorized nodes and authorized_only flag.
	/// 设置授权节点和 authorized_only 标志。
	fn set_authorized_nodes(&mut self, nodes: Vec<OpaquePeerId>, authorized_only: bool) {
		self.extension::<OffchainWorkerExt>()
			.expect("set_authorized_nodes can be called only in the offchain worker context")
			.set_authorized_nodes(nodes, authorized_only)
	}
}

/// Wasm only interface that provides functions for calling into the allocator.
/// Wasm 唯一的接口，提供调用分配器的函数。
#[runtime_interface(wasm_only)]
pub trait Allocator {
	/// Malloc the given number of bytes and return the pointer to the allocated memory location.
	/// malloc 给定的字节数并返回指向已分配内存位置的指针。
	fn malloc(&mut self, size: u32) -> Pointer<u8> {
		self.allocate_memory(size).expect("Failed to allocate memory")
	}

	/// Free the given pointer.
	/// 释放给定的指针。
	fn free(&mut self, ptr: Pointer<u8>) {
		self.deallocate_memory(ptr).expect("Failed to deallocate memory")
	}
}

/// WASM-only interface which allows for aborting the execution in case
/// of an unrecoverable error.
/// 仅 WASM 接口，允许在出现不可恢复的错误时中止执行。
#[runtime_interface(wasm_only)]
pub trait PanicHandler {
	/// Aborts the current execution with the given error message.
	/// 使用给定的错误消息中止当前执行
	#[trap_on_return]
	fn abort_on_panic(&mut self, message: &str) {
		self.register_panic_error_message(message);
	}
}

/// Interface that provides functions for logging from within the runtime.
/// 提供从运行时内进行日志记录的功能的接口。
#[runtime_interface]
pub trait Logging {
	/// Request to print a log message on the host.
	/// 请求在主机上打印日志消息
	/// Note that this will be only displayed if the host is enabled to display log messages with
	/// given level and target.
	///
	/// Instead of using directly, prefer setting up `RuntimeLogger` and using `log` macros.
	fn log(level: LogLevel, target: &str, message: &[u8]) {
		if let Ok(message) = std::str::from_utf8(message) {
			log::log!(target: target, log::Level::from(level), "{}", message)
		}
	}

	/// Returns the max log level used by the host.
	fn max_level() -> LogLevelFilter {
		log::max_level().into()
	}
}

#[derive(Encode, Decode)]
/// Crossing is a helper wrapping any Encode-Decodeable type
/// for transferring over the wasm barrier.
/// Crossing 是包装任何 Encode-Decodeable 类型的助手，用于在 wasm 屏障上传输。
pub struct Crossing<T: Encode + Decode>(T);

impl<T: Encode + Decode> PassBy for Crossing<T> {
	type PassBy = sp_runtime_interface::pass_by::Codec<Self>;
}

impl<T: Encode + Decode> Crossing<T> {
	/// Convert into the inner type
	pub fn into_inner(self) -> T {
		self.0
	}
}

// useful for testing
impl<T> core::default::Default for Crossing<T>
where
	T: core::default::Default + Encode + Decode,
{
	fn default() -> Self {
		Self(Default::default())
	}
}

/// Interface to provide tracing facilities for wasm. Modelled after tokios `tracing`-crate
/// interfaces. See `sp-tracing` for more information.
/// 为 wasm 提供跟踪工具的接口。模仿 tokios `tracing`-crate 接口。有关更多信息，请参阅`sp-tracing`。
#[runtime_interface(wasm_only, no_tracing)]
pub trait WasmTracing {
	/// Whether the span described in `WasmMetadata` should be traced wasm-side
	/// On the host converts into a static Metadata and checks against the global `tracing`
	/// dispatcher.
	///
	/// When returning false the calling code should skip any tracing-related execution. In general
	/// within the same block execution this is not expected to change and it doesn't have to be
	/// checked more than once per metadata. This exists for optimisation purposes but is still not
	/// cheap as it will jump the wasm-native-barrier every time it is called. So an implementation
	/// might chose to cache the result for the execution of the entire block.
	fn enabled(&mut self, metadata: Crossing<sp_tracing::WasmMetadata>) -> bool {
		let metadata: &tracing_core::metadata::Metadata<'static> = (&metadata.into_inner()).into();
		tracing::dispatcher::get_default(|d| d.enabled(metadata))
	}

	/// Open a new span with the given attributes. Return the u64 Id of the span.
	///
	/// On the native side this goes through the default `tracing` dispatcher to register the span
	/// and then calls `clone_span` with the ID to signal that we are keeping it around on the wasm-
	/// side even after the local span is dropped. The resulting ID is then handed over to the wasm-
	/// side.
	fn enter_span(&mut self, span: Crossing<sp_tracing::WasmEntryAttributes>) -> u64 {
		let span: tracing::Span = span.into_inner().into();
		match span.id() {
			Some(id) => tracing::dispatcher::get_default(|d| {
				// inform dispatch that we'll keep the ID around
				// then enter it immediately
				let final_id = d.clone_span(&id);
				d.enter(&final_id);
				final_id.into_u64()
			}),
			_ => 0,
		}
	}

	/// Emit the given event to the global tracer on the native side
	fn event(&mut self, event: Crossing<sp_tracing::WasmEntryAttributes>) {
		event.into_inner().emit();
	}

	/// Signal that a given span-id has been exited. On native, this directly
	/// proxies the span to the global dispatcher.
	fn exit(&mut self, span: u64) {
		tracing::dispatcher::get_default(|d| {
			let id = tracing_core::span::Id::from_u64(span);
			d.exit(&id);
		});
	}
}

#[cfg(all(not(feature = "std"), feature = "with-tracing"))]
mod tracing_setup {
	use super::{wasm_tracing, Crossing};
	use core::sync::atomic::{AtomicBool, Ordering};
	use tracing_core::{
		dispatcher::{set_global_default, Dispatch},
		span::{Attributes, Id, Record},
		Event, Metadata,
	};

	static TRACING_SET: AtomicBool = AtomicBool::new(false);

	/// The PassingTracingSubscriber implements `tracing_core::Subscriber`
	/// and pushes the information across the runtime interface to the host
	struct PassingTracingSubsciber;

	impl tracing_core::Subscriber for PassingTracingSubsciber {
		fn enabled(&self, metadata: &Metadata<'_>) -> bool {
			wasm_tracing::enabled(Crossing(metadata.into()))
		}
		fn new_span(&self, attrs: &Attributes<'_>) -> Id {
			Id::from_u64(wasm_tracing::enter_span(Crossing(attrs.into())))
		}
		fn enter(&self, span: &Id) {
			// Do nothing, we already entered the span previously
		}
		/// Not implemented! We do not support recording values later
		/// Will panic when used.
		fn record(&self, span: &Id, values: &Record<'_>) {
			unimplemented! {} // this usage is not supported
		}
		/// Not implemented! We do not support recording values later
		/// Will panic when used.
		fn record_follows_from(&self, span: &Id, follows: &Id) {
			unimplemented! {} // this usage is not supported
		}
		fn event(&self, event: &Event<'_>) {
			wasm_tracing::event(Crossing(event.into()))
		}
		fn exit(&self, span: &Id) {
			wasm_tracing::exit(span.into_u64())
		}
	}

	/// Initialize tracing of sp_tracing on wasm with `with-tracing` enabled.
	/// Can be called multiple times from within the same process and will only
	/// set the global bridging subscriber once.
	pub fn init_tracing() {
		if TRACING_SET.load(Ordering::Relaxed) == false {
			set_global_default(Dispatch::new(PassingTracingSubsciber {}))
				.expect("We only ever call this once");
			TRACING_SET.store(true, Ordering::Relaxed);
		}
	}
}

#[cfg(not(all(not(feature = "std"), feature = "with-tracing")))]
mod tracing_setup {
	/// Initialize tracing of sp_tracing not necessary – noop. To enable build
	/// without std and with the `with-tracing`-feature.
	pub fn init_tracing() {}
}

pub use tracing_setup::init_tracing;

/// Wasm-only interface that provides functions for interacting with the sandbox.
/// 仅 Wasm 接口，提供与沙箱交互的功能。
#[runtime_interface(wasm_only)]
pub trait Sandbox {
	/// Instantiate a new sandbox instance with the given `wasm_code`.
	/// 使用给定的 `wasm_code` 实例化一个新的沙箱实例。
	fn instantiate(
		&mut self,
		dispatch_thunk: u32,
		wasm_code: &[u8],
		env_def: &[u8],
		state_ptr: Pointer<u8>,
	) -> u32 {
		self.sandbox()
			.instance_new(dispatch_thunk, wasm_code, env_def, state_ptr.into())
			.expect("Failed to instantiate a new sandbox")
	}

	/// Invoke `function` in the sandbox with `sandbox_idx`.
	/// 使用 `sandbox_idx` 在沙箱中调用 `function`。
	fn invoke(
		&mut self,
		instance_idx: u32,
		function: &str,
		args: &[u8],
		return_val_ptr: Pointer<u8>,
		return_val_len: u32,
		state_ptr: Pointer<u8>,
	) -> u32 {
		self.sandbox()
			.invoke(
				instance_idx,
				&function,
				&args,
				return_val_ptr,
				return_val_len,
				state_ptr.into(),
			)
			.expect("Failed to invoke function with sandbox")
	}

	/// Create a new memory instance with the given `initial` and `maximum` size.
	/// 使用给定的“初始”和“最大”大小创建一个新的内存实例。
	fn memory_new(&mut self, initial: u32, maximum: u32) -> u32 {
		self.sandbox()
			.memory_new(initial, maximum)
			.expect("Failed to create new memory with sandbox")
	}

	/// Get the memory starting at `offset` from the instance with `memory_idx` into the buffer.
	/// 从带有 `memory_idx` 的实例中获取从 `offset` 开始的内存到缓冲区中。
	fn memory_get(
		&mut self,
		memory_idx: u32,
		offset: u32,
		buf_ptr: Pointer<u8>,
		buf_len: u32,
	) -> u32 {
		self.sandbox()
			.memory_get(memory_idx, offset, buf_ptr, buf_len)
			.expect("Failed to get memory with sandbox")
	}

	/// Set the memory in the given `memory_idx` to the given value at `offset`.
	/// 将给定 `memory_idx` 中的内存设置为 `offset` 处的给定值。
	fn memory_set(
		&mut self,
		memory_idx: u32,
		offset: u32,
		val_ptr: Pointer<u8>,
		val_len: u32,
	) -> u32 {
		self.sandbox()
			.memory_set(memory_idx, offset, val_ptr, val_len)
			.expect("Failed to set memory with sandbox")
	}

	/// Teardown the memory instance with the given `memory_idx`.
	/// 使用给定的 `memory_idx` 拆除内存实例。
	fn memory_teardown(&mut self, memory_idx: u32) {
		self.sandbox()
			.memory_teardown(memory_idx)
			.expect("Failed to teardown memory with sandbox")
	}

	/// Teardown the sandbox instance with the given `instance_idx`.
	/// 使用给定的“instance_idx”拆除沙箱实例。
	fn instance_teardown(&mut self, instance_idx: u32) {
		self.sandbox()
			.instance_teardown(instance_idx)
			.expect("Failed to teardown sandbox instance")
	}

	/// Get the value from a global with the given `name`. The sandbox is determined by the given
	/// `instance_idx`.
	/// 从具有给定“名称”的全局变量中获取值。沙箱由给定的“instance_idx”决定。
	/// Returns `Some(_)` when the requested global variable could be found.
	/// 当可以找到请求的全局变量时返回 `Some(_)`。
	fn get_global_val(
		&mut self,
		instance_idx: u32,
		name: &str,
	) -> Option<sp_wasm_interface::Value> {
		self.sandbox()
			.get_global_val(instance_idx, name)
			.expect("Failed to get global from sandbox")
	}
}

/// Wasm host functions for managing tasks.
/// 用于管理任务的 Wasm 主机功能。
/// This should not be used directly. Use `sp_tasks` for running parallel tasks instead.
/// 这不应该直接使用。改为使用 `sp_tasks` 来运行并行任务。
#[runtime_interface(wasm_only)]
pub trait RuntimeTasks {
	/// Wasm host function for spawning task.
	/// 用于生成任务的 Wasm 主机功能。
	/// This should not be used directly. Use `sp_tasks::spawn` instead.
	fn spawn(dispatcher_ref: u32, entry: u32, payload: Vec<u8>) -> u64 {
		sp_externalities::with_externalities(|mut ext| {
			let runtime_spawn = ext
				.extension::<RuntimeSpawnExt>()
				.expect("Cannot spawn without dynamic runtime dispatcher (RuntimeSpawnExt)");
			runtime_spawn.spawn_call(dispatcher_ref, entry, payload)
		})
		.expect("`RuntimeTasks::spawn`: called outside of externalities context")
	}

	/// Wasm host function for joining a task.
	/// 用于加入任务的 Wasm 主机功能。
	/// This should not be used directly. Use `join` of `sp_tasks::spawn` result instead.
	fn join(handle: u64) -> Vec<u8> {
		sp_externalities::with_externalities(|mut ext| {
			let runtime_spawn = ext
				.extension::<RuntimeSpawnExt>()
				.expect("Cannot join without dynamic runtime dispatcher (RuntimeSpawnExt)");
			runtime_spawn.join(handle)
		})
		.expect("`RuntimeTasks::join`: called outside of externalities context")
	}
}

/// Allocator used by Substrate when executing the Wasm runtime.
/// Substrate 在执行 Wasm 运行时时使用的分配器。
#[cfg(all(target_arch = "wasm32", not(feature = "std")))]
struct WasmAllocator;

#[cfg(all(target_arch = "wasm32", not(feature = "disable_allocator"), not(feature = "std")))]
#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

#[cfg(all(target_arch = "wasm32", not(feature = "std")))]
mod allocator_impl {
	use super::*;
	use core::alloc::{GlobalAlloc, Layout};

	unsafe impl GlobalAlloc for WasmAllocator {
		unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
			allocator::malloc(layout.size() as u32)
		}

		unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
			allocator::free(ptr)
		}
	}
}

/// A default panic handler for WASM environment.
/// WASM 环境的默认恐慌处理程序。
#[cfg(all(not(feature = "disable_panic_handler"), not(feature = "std")))]
#[panic_handler]
#[no_mangle]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
	let message = sp_std::alloc::format!("{}", info);
	#[cfg(feature = "improved_panic_error_reporting")]
	{
		panic_handler::abort_on_panic(&message);
	}
	#[cfg(not(feature = "improved_panic_error_reporting"))]
	{
		logging::log(LogLevel::Error, "runtime", message.as_bytes());
		core::arch::wasm32::unreachable();
	}
}

/// A default OOM handler for WASM environment.
/// WASM 环境的默认 OOM 处理程序。
#[cfg(all(not(feature = "disable_oom"), not(feature = "std")))]
#[alloc_error_handler]
pub fn oom(_: core::alloc::Layout) -> ! {
	#[cfg(feature = "improved_panic_error_reporting")]
	{
		panic_handler::abort_on_panic("Runtime memory exhausted.");
	}
	#[cfg(not(feature = "improved_panic_error_reporting"))]
	{
		logging::log(LogLevel::Error, "runtime", b"Runtime memory exhausted. Aborting");
		core::arch::wasm32::unreachable();
	}
}

/// Type alias for Externalities implementation used in tests.
/// 测试中使用的 Externalities 实现的类型别名。
#[cfg(feature = "std")]
pub type TestExternalities = sp_state_machine::TestExternalities<sp_core::Blake2Hasher>;

/// The host functions Substrate provides for the Wasm runtime environment.
/// Substrate 为 Wasm 运行时环境提供的宿主函数。
/// All these host functions will be callable from inside the Wasm environment.
/// 所有这些主机函数都可以从 Wasm 环境内部调用。
#[cfg(feature = "std")]
pub type SubstrateHostFunctions = (
	storage::HostFunctions,
	default_child_storage::HostFunctions,
	misc::HostFunctions,
	wasm_tracing::HostFunctions,
	offchain::HostFunctions,
	crypto::HostFunctions,
	hashing::HostFunctions,
	allocator::HostFunctions,
	panic_handler::HostFunctions,
	logging::HostFunctions,
	sandbox::HostFunctions,
	crate::trie::HostFunctions,
	offchain_index::HostFunctions,
	runtime_tasks::HostFunctions,
	transaction_index::HostFunctions,
);

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::{
		crypto::UncheckedInto, map, storage::Storage, testing::TaskExecutor,
		traits::TaskExecutorExt,
	};
	use sp_state_machine::BasicExternalities;
	use std::any::TypeId;

	#[test]
	fn storage_works() {
		let mut t = BasicExternalities::default();
		t.execute_with(|| {
			assert_eq!(storage::get(b"hello"), None);
			storage::set(b"hello", b"world");
			assert_eq!(storage::get(b"hello"), Some(b"world".to_vec()));
			assert_eq!(storage::get(b"foo"), None);
			storage::set(b"foo", &[1, 2, 3][..]);
		});

		t = BasicExternalities::new(Storage {
			top: map![b"foo".to_vec() => b"bar".to_vec()],
			children_default: map![],
		});

		t.execute_with(|| {
			assert_eq!(storage::get(b"hello"), None);
			assert_eq!(storage::get(b"foo"), Some(b"bar".to_vec()));
		});

		let value = vec![7u8; 35];
		let storage =
			Storage { top: map![b"foo00".to_vec() => value.clone()], children_default: map![] };
		t = BasicExternalities::new(storage);

		t.execute_with(|| {
			assert_eq!(storage::get(b"hello"), None);
			assert_eq!(storage::get(b"foo00"), Some(value.clone()));
		});
	}

	#[test]
	fn read_storage_works() {
		let value = b"\x0b\0\0\0Hello world".to_vec();
		let mut t = BasicExternalities::new(Storage {
			top: map![b":test".to_vec() => value.clone()],
			children_default: map![],
		});

		t.execute_with(|| {
			let mut v = [0u8; 4];
			assert_eq!(storage::read(b":test", &mut v[..], 0).unwrap(), value.len() as u32);
			assert_eq!(v, [11u8, 0, 0, 0]);
			let mut w = [0u8; 11];
			assert_eq!(storage::read(b":test", &mut w[..], 4).unwrap(), value.len() as u32 - 4);
			assert_eq!(&w, b"Hello world");
		});
	}

	#[test]
	fn clear_prefix_works() {
		let mut t = BasicExternalities::new(Storage {
			top: map![
				b":a".to_vec() => b"\x0b\0\0\0Hello world".to_vec(),
				b":abcd".to_vec() => b"\x0b\0\0\0Hello world".to_vec(),
				b":abc".to_vec() => b"\x0b\0\0\0Hello world".to_vec(),
				b":abdd".to_vec() => b"\x0b\0\0\0Hello world".to_vec()
			],
			children_default: map![],
		});

		t.execute_with(|| {
			assert!(matches!(
				storage::clear_prefix(b":abc", None),
				KillStorageResult::AllRemoved(2)
			));

			assert!(storage::get(b":a").is_some());
			assert!(storage::get(b":abdd").is_some());
			assert!(storage::get(b":abcd").is_none());
			assert!(storage::get(b":abc").is_none());
		});
	}

	#[test]
	fn batch_verify_start_finish_works() {
		let mut ext = BasicExternalities::default();
		ext.register_extension(TaskExecutorExt::new(TaskExecutor::new()));

		ext.execute_with(|| {
			crypto::start_batch_verify();
		});

		assert!(ext.extensions().get_mut(TypeId::of::<VerificationExt>()).is_some());

		ext.execute_with(|| {
			assert!(crypto::finish_batch_verify());
		});

		assert!(ext.extensions().get_mut(TypeId::of::<VerificationExt>()).is_none());
	}

	#[test]
	fn long_sr25519_batching() {
		let mut ext = BasicExternalities::default();
		ext.register_extension(TaskExecutorExt::new(TaskExecutor::new()));
		ext.execute_with(|| {
			let pair = sr25519::Pair::generate_with_phrase(None).0;
			crypto::start_batch_verify();
			for it in 0..70 {
				let msg = format!("Schnorrkel {}!", it);
				let signature = pair.sign(msg.as_bytes());
				crypto::sr25519_batch_verify(&signature, msg.as_bytes(), &pair.public());
			}

			// push invlaid
			crypto::sr25519_batch_verify(&zero_sr_sig(), &Vec::new(), &zero_sr_pub());
			assert!(!crypto::finish_batch_verify());

			crypto::start_batch_verify();
			for it in 0..70 {
				let msg = format!("Schnorrkel {}!", it);
				let signature = pair.sign(msg.as_bytes());
				crypto::sr25519_batch_verify(&signature, msg.as_bytes(), &pair.public());
			}
			assert!(crypto::finish_batch_verify());
		});
	}

	fn zero_ed_pub() -> ed25519::Public {
		[0u8; 32].unchecked_into()
	}

	fn zero_ed_sig() -> ed25519::Signature {
		ed25519::Signature::from_raw([0u8; 64])
	}

	fn zero_sr_pub() -> sr25519::Public {
		[0u8; 32].unchecked_into()
	}

	fn zero_sr_sig() -> sr25519::Signature {
		sr25519::Signature::from_raw([0u8; 64])
	}

	#[test]
	fn batching_works() {
		let mut ext = BasicExternalities::default();
		ext.register_extension(TaskExecutorExt::new(TaskExecutor::new()));

		ext.execute_with(|| {
			// invalid ed25519 signature
			crypto::start_batch_verify();
			crypto::ed25519_batch_verify(&zero_ed_sig(), &Vec::new(), &zero_ed_pub());
			assert!(!crypto::finish_batch_verify());

			// 2 valid ed25519 signatures
			crypto::start_batch_verify();

			let pair = ed25519::Pair::generate_with_phrase(None).0;
			let msg = b"Important message";
			let signature = pair.sign(msg);
			crypto::ed25519_batch_verify(&signature, msg, &pair.public());

			let pair = ed25519::Pair::generate_with_phrase(None).0;
			let msg = b"Even more important message";
			let signature = pair.sign(msg);
			crypto::ed25519_batch_verify(&signature, msg, &pair.public());

			assert!(crypto::finish_batch_verify());

			// 1 valid, 1 invalid ed25519 signature
			crypto::start_batch_verify();

			let pair = ed25519::Pair::generate_with_phrase(None).0;
			let msg = b"Important message";
			let signature = pair.sign(msg);
			crypto::ed25519_batch_verify(&signature, msg, &pair.public());

			crypto::ed25519_batch_verify(&zero_ed_sig(), &Vec::new(), &zero_ed_pub());

			assert!(!crypto::finish_batch_verify());

			// 1 valid ed25519, 2 valid sr25519
			crypto::start_batch_verify();

			let pair = ed25519::Pair::generate_with_phrase(None).0;
			let msg = b"Ed25519 batching";
			let signature = pair.sign(msg);
			crypto::ed25519_batch_verify(&signature, msg, &pair.public());

			let pair = sr25519::Pair::generate_with_phrase(None).0;
			let msg = b"Schnorrkel rules";
			let signature = pair.sign(msg);
			crypto::sr25519_batch_verify(&signature, msg, &pair.public());

			let pair = sr25519::Pair::generate_with_phrase(None).0;
			let msg = b"Schnorrkel batches!";
			let signature = pair.sign(msg);
			crypto::sr25519_batch_verify(&signature, msg, &pair.public());

			assert!(crypto::finish_batch_verify());

			// 1 valid sr25519, 1 invalid sr25519
			crypto::start_batch_verify();

			let pair = sr25519::Pair::generate_with_phrase(None).0;
			let msg = b"Schnorrkcel!";
			let signature = pair.sign(msg);
			crypto::sr25519_batch_verify(&signature, msg, &pair.public());

			crypto::sr25519_batch_verify(&zero_sr_sig(), &Vec::new(), &zero_sr_pub());

			assert!(!crypto::finish_batch_verify());
		});
	}
}
