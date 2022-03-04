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

//! Transaction validity interface.
//! 交易验证接口

use crate::{
	codec::{Decode, Encode},
	RuntimeDebug,
};
use sp_std::prelude::*;

/// Priority for a transaction. Additive. Higher is better.
/// 事务的优先级。累加。越高越好。
pub type TransactionPriority = u64;

/// Minimum number of blocks a transaction will remain valid for.
/// `TransactionLongevity::max_value()` means "forever".
/// 交易将保持有效的最小块数。 `TransactionLongevity::max_value()` 的意思是“永远”。
pub type TransactionLongevity = u64;

/// Tag for a transaction. No two transactions with the same tag should be placed on-chain.
/// 交易标签。不应将具有相同标签的两个交易放在链上。
pub type TransactionTag = Vec<u8>;

/// An invalid transaction validity.
/// 无效的交易有效性。
#[derive(Clone, PartialEq, Eq, Encode, Decode, Copy, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum InvalidTransaction {
	/// The call of the transaction is not expected.
	/// 调用超出预期
	Call,
	/// General error to do with the inability to pay some fees (e.g. account balance too low).
	/// 与无法支付某些费用有关的一般错误（例如，账户余额太低）。
	Payment,
	/// General error to do with the transaction not yet being valid (e.g. nonce too high).
	/// 与尚未生效的交易有关的一般错误（例如，nonce 太高）。
	Future,
	/// General error to do with the transaction being outdated (e.g. nonce too low).
	/// 与交易过时有关的一般错误（例如，nonce 太低）。
	Stale,
	/// General error to do with the transaction's proofs (e.g. signature).
	/// 与交易证明（例如签名）有关的一般错误。
	/// # Possible causes
	///
	/// When using a signed extension that provides additional data for signing, it is required
	/// that the signing and the verifying side use the same additional data. Additional
	/// data will only be used to generate the signature, but will not be part of the transaction
	/// itself. As the verifying side does not know which additional data was used while signing
	/// it will only be able to assume a bad signature and cannot express a more meaningful error.
	/// 当使用为签名提供附加数据的签名扩展时，要求签名方和验证方使用相同的附加数据。附加数据将仅用于生成签名，但不会成为交易本身的一部分。
	/// 由于验证方不知道在签名时使用了哪些附加数据，因此它只能假设一个错误的签名并且不能表达更有意义的错误。
	BadProof,
	/// The transaction birth block is ancient.
	/// 交易诞生区块是古老的。
	/// # Possible causes
	///
	/// For `FRAME`-based runtimes this would be caused by `current block number
	/// - Era::birth block number > BlockHashCount`. (e.g. in Polkadot `BlockHashCount` = 2400, so
	///   a
	/// transaction with birth block number 1337 would be valid up until block number 1337 + 2400,
	/// after which point the transaction would be considered to have an ancient birth block.)
	AncientBirthBlock,
	/// The transaction would exhaust the resources of current block.
	/// 该交易将耗尽当前区块的资源。
	/// The transaction might be valid, but there are not enough resources
	/// left in the current block.
	/// 交易可能是有效的，但当前块中没有足够的资源。
	ExhaustsResources,
	/// Any other custom invalid validity that is not covered by this enum.
	/// 此枚举未涵盖的任何其他自定义无效有效性
	Custom(u8),
	/// An extrinsic with a Mandatory dispatch resulted in Error. This is indicative of either a
	/// malicious validator or a buggy `provide_inherent`. In any case, it can result in
	/// dangerously overweight blocks and therefore if found, invalidates the block.
	/// 具有强制调度的外部导致错误。这表明存在恶意验证器或有问题的“provide_inherent”。在任何情况下，它都可能导致危险的超重块，因此如果发现，会使块无效。
	BadMandatory,
	/// A transaction with a mandatory dispatch. This is invalid; only inherent extrinsics are
	/// allowed to have mandatory dispatches.
	/// 具有强制生效的事务。这是无效的；只有固有的交易才允许强制。
	MandatoryDispatch,
	/// The sending address is disabled or known to be invalid.
	/// 发送地址被禁用或已知无效。
	BadSigner,
}

impl InvalidTransaction {
	/// Returns if the reason for the invalidity was block resource exhaustion.
	/// 如果无效的原因是块资源耗尽，则返回。
	pub fn exhausted_resources(&self) -> bool {
		matches!(self, Self::ExhaustsResources)
	}

	/// Returns if the reason for the invalidity was a mandatory call failing.
	/// 如果无效的原因是强制调用失败，则返回。
	pub fn was_mandatory(&self) -> bool {
		matches!(self, Self::BadMandatory)
	}
}

impl From<InvalidTransaction> for &'static str {
	fn from(invalid: InvalidTransaction) -> &'static str {
		match invalid {
			InvalidTransaction::Call => "Transaction call is not expected",
			InvalidTransaction::Future => "Transaction will be valid in the future",
			InvalidTransaction::Stale => "Transaction is outdated",
			InvalidTransaction::BadProof => "Transaction has a bad signature",
			InvalidTransaction::AncientBirthBlock => "Transaction has an ancient birth block",
			InvalidTransaction::ExhaustsResources => "Transaction would exhaust the block limits",
			InvalidTransaction::Payment =>
				"Inability to pay some fees (e.g. account balance too low)",
			InvalidTransaction::BadMandatory =>
				"A call was labelled as mandatory, but resulted in an Error.",
			InvalidTransaction::MandatoryDispatch =>
				"Transaction dispatch is mandatory; transactions may not have mandatory dispatches.",
			InvalidTransaction::Custom(_) => "InvalidTransaction custom error",
			InvalidTransaction::BadSigner => "Invalid signing address",
		}
	}
}

/// An unknown transaction validity.
/// 未知的交易有效性。
#[derive(Clone, PartialEq, Eq, Encode, Decode, Copy, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum UnknownTransaction {
	/// Could not lookup some information that is required to validate the transaction.
	/// 无法查找验证交易所需的某些信息。
	CannotLookup,
	/// No validator found for the given unsigned transaction.
	/// 没有为给定的未签名交易找到验证者。
	NoUnsignedValidator,
	/// Any other custom unknown validity that is not covered by this enum.
	/// 此枚举未涵盖的任何其他自定义未知有效性。
	Custom(u8),
}

impl From<UnknownTransaction> for &'static str {
	fn from(unknown: UnknownTransaction) -> &'static str {
		match unknown {
			UnknownTransaction::CannotLookup =>
				"Could not lookup information required to validate the transaction",
			UnknownTransaction::NoUnsignedValidator =>
				"Could not find an unsigned validator for the unsigned transaction",
			UnknownTransaction::Custom(_) => "UnknownTransaction custom error",
		}
	}
}

/// Errors that can occur while checking the validity of a transaction.
/// 检查交易有效性时可能发生的错误。
#[derive(Clone, PartialEq, Eq, Encode, Decode, Copy, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionValidityError {
	/// The transaction is invalid.
	/// 交易无效。
	Invalid(InvalidTransaction),
	/// Transaction validity can't be determined.
	/// 无法确定交易有效性。
	Unknown(UnknownTransaction),
}

impl TransactionValidityError {
	/// Returns `true` if the reason for the error was block resource exhaustion.
	pub fn exhausted_resources(&self) -> bool {
		match self {
			Self::Invalid(e) => e.exhausted_resources(),
			Self::Unknown(_) => false,
		}
	}

	/// Returns `true` if the reason for the error was it being a mandatory dispatch that could not
	/// be completed successfully.
	pub fn was_mandatory(&self) -> bool {
		match self {
			Self::Invalid(e) => e.was_mandatory(),
			Self::Unknown(_) => false,
		}
	}
}

impl From<TransactionValidityError> for &'static str {
	fn from(err: TransactionValidityError) -> &'static str {
		match err {
			TransactionValidityError::Invalid(invalid) => invalid.into(),
			TransactionValidityError::Unknown(unknown) => unknown.into(),
		}
	}
}

impl From<InvalidTransaction> for TransactionValidityError {
	fn from(err: InvalidTransaction) -> Self {
		TransactionValidityError::Invalid(err)
	}
}

impl From<UnknownTransaction> for TransactionValidityError {
	fn from(err: UnknownTransaction) -> Self {
		TransactionValidityError::Unknown(err)
	}
}

#[cfg(feature = "std")]
impl std::error::Error for TransactionValidityError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		None
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for TransactionValidityError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s: &'static str = (*self).into();
		write!(f, "{}", s)
	}
}

/// Information on a transaction's validity and, if valid, on how it relates to other transactions.
/// 有关交易有效性的信息，如果有效，则说明它与其他交易的关系。
pub type TransactionValidity = Result<ValidTransaction, TransactionValidityError>;

impl From<InvalidTransaction> for TransactionValidity {
	fn from(invalid_transaction: InvalidTransaction) -> Self {
		Err(TransactionValidityError::Invalid(invalid_transaction))
	}
}

impl From<UnknownTransaction> for TransactionValidity {
	fn from(unknown_transaction: UnknownTransaction) -> Self {
		Err(TransactionValidityError::Unknown(unknown_transaction))
	}
}

/// The source of the transaction.
/// 交易的来源。
/// Depending on the source we might apply different validation schemes.
/// For instance we can disallow specific kinds of transactions if they were not produced
/// by our local node (for instance off-chain workers).
/// 根据来源，我们可能会应用不同的验证方案。
/// 例如，如果特定类型的交易不是由我们的本地节点（例如链下工作人员）产生的，我们可以禁止它们。
#[derive(
	Copy, Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, parity_util_mem::MallocSizeOf,
)]
pub enum TransactionSource {
	/// Transaction is already included in block.
	/// 交易已经被包含在区块中
	/// This means that we can't really tell where the transaction is coming from,
	/// since it's already in the received block. Note that the custom validation logic
	/// using either `Local` or `External` should most likely just allow `InBlock`
	/// transactions as well.
	/// 这意味着我们无法真正判断交易的来源，因为它已经在接收的块中。
	/// 请注意，使用“Local”或“External”的自定义验证逻辑很可能也只允许“InBlock”交易。
	InBlock,

	/// Transaction is coming from a local source.
	/// 交易来自本地来源。
	/// This means that the transaction was produced internally by the node
	/// (for instance an Off-Chain Worker, or an Off-Chain Call), as opposed
	/// to being received over the network.
	/// 这意味着交易是由节点内部产生的（例如链外工作人员或链外调用），而不是通过网络接收。
	Local,

	/// Transaction has been received externally.
	/// 交易从外面发送来。
	/// This means the transaction has been received from (usually) "untrusted" source,
	/// for instance received over the network or RPC.
	/// 这意味着交易是从（通常）“不受信任的”来源接收的，例如通过网络或 RPC 接收的。
	External,
}

/// Information concerning a valid transaction.
/// 有关有效交易的信息。
#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct ValidTransaction {
	/// Priority of the transaction.
	/// 交易的优先级
	/// Priority determines the ordering of two transactions that have all
	/// their dependencies (required tags) satisfied.
	/// 优先级确定满足所有依赖项（必需标签）的两个事务的顺序。
	pub priority: TransactionPriority,
	/// Transaction dependencies
	/// 交易依赖
	/// A non-empty list signifies that some other transactions which provide
	/// given tags are required to be included before that one.
	/// 非空列表表示需要在该列表之前包含一些提供给定标签的其他交易。
	pub requires: Vec<TransactionTag>,
	/// Provided tags
	/// 提供的标签
	/// A list of tags this transaction provides. Successfully importing the transaction
	/// will enable other transactions that depend on (require) those tags to be included as well.
	/// Provided and required tags allow Substrate to build a dependency graph of transactions
	/// and import them in the right (linear) order.
	/// 此交易提供的标签列表。成功导入交易将使依赖（需要）这些标签的其他交易也被包括在内。
	/// 提供和必需的标签允许 Substrate 构建交易的依赖图并以正确的（线性）顺序导入它们。
	pub provides: Vec<TransactionTag>,
	/// Transaction longevity
	/// 交易寿命
	/// Longevity describes minimum number of blocks the validity is correct.
	/// After this period transaction should be removed from the pool or revalidated.
	/// 寿命描述了有效性正确的最小块数。在此期间之后，交易应从池中删除或重新验证。
	pub longevity: TransactionLongevity,
	/// A flag indicating if the transaction should be propagated to other peers.
	/// 指示事务是否应传播到其他对等方的标志。
	/// By setting `false` here the transaction will still be considered for
	/// including in blocks that are authored on the current node, but will
	/// never be sent to other peers.
	/// 通过在此处设置“false”，交易仍将被考虑包含在当前节点上创建的块中，但永远不会发送给其他对等方。
	pub propagate: bool,
}

impl Default for ValidTransaction {
	fn default() -> Self {
		Self {
			priority: 0,
			requires: vec![],
			provides: vec![],
			longevity: TransactionLongevity::max_value(),
			propagate: true,
		}
	}
}

impl ValidTransaction {
	/// Initiate `ValidTransaction` builder object with a particular prefix for tags.
	/// 使用标签的特定前缀启动“ValidTransaction”构建器对象。
	/// To avoid conflicts between different parts in runtime it's recommended to build `requires`
	/// and `provides` tags with a unique prefix.
	/// 为了避免运行时不同部分之间的冲突，建议构建带有唯一前缀的“requires”和“provides”标签。
	pub fn with_tag_prefix(prefix: &'static str) -> ValidTransactionBuilder {
		ValidTransactionBuilder { prefix: Some(prefix), validity: Default::default() }
	}

	/// Combine two instances into one, as a best effort. This will take the superset of each of the
	/// `provides` and `requires` tags, it will sum the priorities, take the minimum longevity and
	/// the logic *And* of the propagate flags.
	/// 尽最大努力将两个实例合二为一。这将采用每个“provides”和“requires”标签的超集，它将优先级求和，采用最小寿命和传播标志的逻辑与。
	pub fn combine_with(mut self, mut other: ValidTransaction) -> Self {
		Self {
			priority: self.priority.saturating_add(other.priority),
			requires: {
				self.requires.append(&mut other.requires);
				self.requires
			},
			provides: {
				self.provides.append(&mut other.provides);
				self.provides
			},
			longevity: self.longevity.min(other.longevity),
			propagate: self.propagate && other.propagate,
		}
	}
}

/// `ValidTransaction` builder.
/// `ValidTransaction` 构建器。
///
/// Allows to easily construct `ValidTransaction` and most importantly takes care of
/// prefixing `requires` and `provides` tags to avoid conflicts.
/// 允许轻松构造 `ValidTransaction`，最重要的是注意前缀 `requires` 和 `provides` 标签以避免冲突。
#[derive(Default, Clone, RuntimeDebug)]
pub struct ValidTransactionBuilder {
	prefix: Option<&'static str>,
	validity: ValidTransaction,
}

impl ValidTransactionBuilder {
	/// Set the priority of a transaction.
	/// 设置交易优先级
	/// Note that the final priority for `FRAME` is combined from all `SignedExtension`s.
	/// Most likely for unsigned transactions you want the priority to be higher
	/// than for regular transactions. We recommend exposing a base priority for unsigned
	/// transactions as a runtime module parameter, so that the runtime can tune inter-module
	/// priorities.
	/// 请注意，“FRAME”的最终优先级是由所有“SignedExtension”组合而成的。
	/// 很可能对于未签名的交易，您希望优先级高于常规交易。
	/// 我们建议将未签名事务的基本优先级公开为运行时模块参数，以便运行时可以调整模块间优先级。
	pub fn priority(mut self, priority: TransactionPriority) -> Self {
		self.validity.priority = priority;
		self
	}

	/// Set the longevity of a transaction.
	/// 设置交易的寿命
	/// By default the transaction will be considered valid forever and will not be revalidated
	/// by the transaction pool. It's recommended though to set the longevity to a finite value
	/// though. If unsure, it's also reasonable to expose this parameter via module configuration
	/// and let the runtime decide.
	/// 默认情况下，交易将被视为永久有效，不会被交易池重新验证。
	/// 不过，建议将寿命设置为有限值。如果不确定，通过模块配置公开这个参数并让运行时决定也是合理的。
	pub fn longevity(mut self, longevity: TransactionLongevity) -> Self {
		self.validity.longevity = longevity;
		self
	}

	/// Set the propagate flag.
	/// 设置传播标志
	/// Set to `false` if the transaction is not meant to be gossiped to peers. Combined with
	/// `TransactionSource::Local` validation it can be used to have special kind of
	/// transactions that are only produced and included by the validator nodes.
	/// 如果交易不打算向对等方传播，则设置为“false”。
	/// 结合 `TransactionSource::Local` 验证，它可以用于具有仅由验证器节点生成和包含的特殊类型的事务。
	pub fn propagate(mut self, propagate: bool) -> Self {
		self.validity.propagate = propagate;
		self
	}

	/// Add a `TransactionTag` to the set of required tags.
	/// 将“TransactionTag”添加到所需标签集。
	/// The tag will be encoded and prefixed with module prefix (if any).
	/// If you'd rather add a raw `require` tag, consider using `#combine_with` method.
	/// 标签将被编码并以模块前缀（如果有）作为前缀。如果您想添加原始的 `require` 标签，请考虑使用 `combine_with` 方法。
	pub fn and_requires(mut self, tag: impl Encode) -> Self {
		self.validity.requires.push(match self.prefix.as_ref() {
			Some(prefix) => (prefix, tag).encode(),
			None => tag.encode(),
		});
		self
	}

	/// Add a `TransactionTag` to the set of provided tags.
	/// 将“TransactionTag”添加到提供的标签集。
	/// The tag will be encoded and prefixed with module prefix (if any).
	/// If you'd rather add a raw `require` tag, consider using `#combine_with` method.
	/// 标签将被编码并以模块前缀（如果有）作为前缀。
	/// 如果您想添加原始的 `require` 标签，请考虑使用 `combine_with` 方法。
	pub fn and_provides(mut self, tag: impl Encode) -> Self {
		self.validity.provides.push(match self.prefix.as_ref() {
			Some(prefix) => (prefix, tag).encode(),
			None => tag.encode(),
		});
		self
	}

	/// Augment the builder with existing `ValidTransaction`.
	/// 使用现有的 `ValidTransaction` 增强构建器。
	/// This method does add the prefix to `require` or `provides` tags.
	/// 此方法确实将前缀添加到 `require` 或 `provides` 标签。
	pub fn combine_with(mut self, validity: ValidTransaction) -> Self {
		self.validity = core::mem::take(&mut self.validity).combine_with(validity);
		self
	}

	/// Finalize the builder and produce `TransactionValidity`.
	/// 完成构建器并生成“TransactionValidity”。
	/// Note the result will always be `Ok`. Use `Into` to produce `ValidTransaction`.
	/// 请注意，结果将始终为“Ok”。使用 `Into` 产生 `Valid Transaction`。
	pub fn build(self) -> TransactionValidity {
		self.into()
	}
}

impl From<ValidTransactionBuilder> for TransactionValidity {
	fn from(builder: ValidTransactionBuilder) -> Self {
		Ok(builder.into())
	}
}

impl From<ValidTransactionBuilder> for ValidTransaction {
	fn from(builder: ValidTransactionBuilder) -> Self {
		builder.validity
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_encode_and_decode() {
		let v: TransactionValidity = Ok(ValidTransaction {
			priority: 5,
			requires: vec![vec![1, 2, 3, 4]],
			provides: vec![vec![4, 5, 6]],
			longevity: 42,
			propagate: false,
		});

		let encoded = v.encode();
		assert_eq!(
			encoded,
			vec![
				0, 5, 0, 0, 0, 0, 0, 0, 0, 4, 16, 1, 2, 3, 4, 4, 12, 4, 5, 6, 42, 0, 0, 0, 0, 0, 0,
				0, 0
			]
		);

		// decode back
		assert_eq!(TransactionValidity::decode(&mut &*encoded), Ok(v));
	}

	#[test]
	fn builder_should_prefix_the_tags() {
		const PREFIX: &str = "test";
		let a: ValidTransaction = ValidTransaction::with_tag_prefix(PREFIX)
			.and_requires(1)
			.and_requires(2)
			.and_provides(3)
			.and_provides(4)
			.propagate(false)
			.longevity(5)
			.priority(3)
			.priority(6)
			.into();
		assert_eq!(
			a,
			ValidTransaction {
				propagate: false,
				longevity: 5,
				priority: 6,
				requires: vec![(PREFIX, 1).encode(), (PREFIX, 2).encode()],
				provides: vec![(PREFIX, 3).encode(), (PREFIX, 4).encode()],
			}
		);
	}
}
