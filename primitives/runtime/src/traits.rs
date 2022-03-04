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

//! Primitives for the runtime modules.
//! 运行时模块的原语。

use crate::{
	codec::{Codec, Decode, Encode, MaxEncodedLen},
	generic::Digest,
	scale_info::{MetaType, StaticTypeInfo, TypeInfo},
	transaction_validity::{
		TransactionSource, TransactionValidity, TransactionValidityError, UnknownTransaction,
		ValidTransaction,
	},
	DispatchResult,
};
use impl_trait_for_tuples::impl_for_tuples;
#[cfg(feature = "std")]
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp_application_crypto::AppKey;
pub use sp_arithmetic::traits::{
	AtLeast32Bit, AtLeast32BitUnsigned, Bounded, CheckedAdd, CheckedDiv, CheckedMul, CheckedShl,
	CheckedShr, CheckedSub, IntegerSquareRoot, One, SaturatedConversion, Saturating,
	UniqueSaturatedFrom, UniqueSaturatedInto, Zero,
};
use sp_core::{self, storage::StateVersion, Hasher, RuntimeDebug, TypeId};
use sp_std::{
	self,
	convert::{TryFrom, TryInto},
	fmt::Debug,
	marker::PhantomData,
	prelude::*,
};
#[cfg(feature = "std")]
use std::fmt::Display;
#[cfg(feature = "std")]
use std::str::FromStr;

/// A lazy value.
/// 一个懒惰的值
pub trait Lazy<T: ?Sized> {
	/// Get a reference to the underlying value.
	/// 获取对基础价值的引用。
	/// This will compute the value if the function is invoked for the first time.
	/// 如果第一次调用该函数，这将计算该值。
	fn get(&mut self) -> &T;
}

impl<'a> Lazy<[u8]> for &'a [u8] {
	fn get(&mut self) -> &[u8] {
		&**self
	}
}

/// Some type that is able to be collapsed into an account ID. It is not possible to recreate the
/// original value from the account ID.
/// 某种可以折叠成帐户 ID 的类型。无法从帐户 ID 重新创建原始值。
pub trait IdentifyAccount {
	/// The account ID that this can be transformed into.
	/// 这可以转换成的帐户 ID。
	type AccountId;
	/// Transform into an account.
	/// 转换为帐户id。
	fn into_account(self) -> Self::AccountId;
}

impl IdentifyAccount for sp_core::ed25519::Public {
	type AccountId = Self;
	fn into_account(self) -> Self {
		self
	}
}

impl IdentifyAccount for sp_core::sr25519::Public {
	type AccountId = Self;
	fn into_account(self) -> Self {
		self
	}
}

impl IdentifyAccount for sp_core::ecdsa::Public {
	type AccountId = Self;
	fn into_account(self) -> Self {
		self
	}
}

/// Means of signature verification.
/// 签名验证的手段。
pub trait Verify {
	/// Type of the signer.
	/// 签名者的类型。
	type Signer: IdentifyAccount;
	/// Verify a signature.
	/// 验证一个签名
	/// Return `true` if signature is valid for the value.
	/// 如果签名对该值有效，则返回 `true`。
	fn verify<L: Lazy<[u8]>>(
		&self,
		msg: L,
		signer: &<Self::Signer as IdentifyAccount>::AccountId,
	) -> bool;
}

impl Verify for sp_core::ed25519::Signature {
	type Signer = sp_core::ed25519::Public;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::ed25519::Public) -> bool {
		sp_io::crypto::ed25519_verify(self, msg.get(), signer)
	}
}

impl Verify for sp_core::sr25519::Signature {
	type Signer = sp_core::sr25519::Public;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::sr25519::Public) -> bool {
		sp_io::crypto::sr25519_verify(self, msg.get(), signer)
	}
}

impl Verify for sp_core::ecdsa::Signature {
	type Signer = sp_core::ecdsa::Public;
	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::ecdsa::Public) -> bool {
		match sp_io::crypto::secp256k1_ecdsa_recover_compressed(
			self.as_ref(),
			&sp_io::hashing::blake2_256(msg.get()),
		) {
			Ok(pubkey) => signer.as_ref() == &pubkey[..],
			_ => false,
		}
	}
}

/// Means of signature verification of an application key.
/// 应用程序密钥的签名验证方法。
pub trait AppVerify {
	/// Type of the signer.
	/// 签名者类型
	type AccountId;
	/// Verify a signature. Return `true` if signature is valid for the value.
	/// 验证签名。如果签名对该值有效，则返回 `true`。
	fn verify<L: Lazy<[u8]>>(&self, msg: L, signer: &Self::AccountId) -> bool;
}

impl<
		S: Verify<Signer = <<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic>
			+ From<T>,
		T: sp_application_crypto::Wraps<Inner = S>
			+ sp_application_crypto::AppKey
			+ sp_application_crypto::AppSignature
			+ AsRef<S>
			+ AsMut<S>
			+ From<S>,
	> AppVerify for T
where
	<S as Verify>::Signer: IdentifyAccount<AccountId = <S as Verify>::Signer>,
	<<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic: IdentifyAccount<
		AccountId = <<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic,
	>,
{
	type AccountId = <T as AppKey>::Public;
	fn verify<L: Lazy<[u8]>>(&self, msg: L, signer: &<T as AppKey>::Public) -> bool {
		use sp_application_crypto::IsWrappedBy;
		let inner: &S = self.as_ref();
		let inner_pubkey =
			<<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic::from_ref(&signer);
		Verify::verify(inner, msg, inner_pubkey)
	}
}

/// An error type that indicates that the origin is invalid.
/// 指示源无效的错误类型。
#[derive(Encode, Decode, RuntimeDebug)]
pub struct BadOrigin;

impl From<BadOrigin> for &'static str {
	fn from(_: BadOrigin) -> &'static str {
		"Bad origin"
	}
}

/// An error that indicates that a lookup failed.
/// 指示查找失败的错误。
#[derive(Encode, Decode, RuntimeDebug)]
pub struct LookupError;

impl From<LookupError> for &'static str {
	fn from(_: LookupError) -> &'static str {
		"Can not lookup"
	}
}

impl From<LookupError> for TransactionValidityError {
	fn from(_: LookupError) -> Self {
		UnknownTransaction::CannotLookup.into()
	}
}

/// Means of changing one type into another in a manner dependent on the source type.
/// 以依赖于源类型的方式将一种类型更改为另一种类型的方法。
pub trait Lookup {
	/// Type to lookup from.
	/// 查找来源
	type Source;
	/// Type to lookup into.
	/// 查找返回类型
	type Target;
	/// Attempt a lookup.
	/// 尝试一次查找
	fn lookup(&self, s: Self::Source) -> Result<Self::Target, LookupError>;
}

/// Means of changing one type into another in a manner dependent on the source type.
/// This variant is different to `Lookup` in that it doesn't (can cannot) require any
/// context.
/// 以依赖于源类型的方式将一种类型更改为另一种类型的方法。此变体与“Lookup”不同，因为它不需要（不能）任何上下文。
pub trait StaticLookup {
	/// Type to lookup from.
	type Source: Codec + Clone + PartialEq + Debug + TypeInfo;
	/// Type to lookup into.
	type Target;
	/// Attempt a lookup.
	fn lookup(s: Self::Source) -> Result<Self::Target, LookupError>;
	/// Convert from Target back to Source.
	/// 回退到source
	fn unlookup(t: Self::Target) -> Self::Source;
}

/// A lookup implementation returning the input value.
/// 返回输入值的查找实现。
#[derive(Default)]
pub struct IdentityLookup<T>(PhantomData<T>);
impl<T: Codec + Clone + PartialEq + Debug + TypeInfo> StaticLookup for IdentityLookup<T> {
	type Source = T;
	type Target = T;
	fn lookup(x: T) -> Result<T, LookupError> {
		Ok(x)
	}
	fn unlookup(x: T) -> T {
		x
	}
}

impl<T> Lookup for IdentityLookup<T> {
	type Source = T;
	type Target = T;
	fn lookup(&self, x: T) -> Result<T, LookupError> {
		Ok(x)
	}
}

/// A lookup implementation returning the `AccountId` from a `MultiAddress`.
/// 从“MultiAddress”返回“AccountId”的查找实现。
pub struct AccountIdLookup<AccountId, AccountIndex>(PhantomData<(AccountId, AccountIndex)>);
impl<AccountId, AccountIndex> StaticLookup for AccountIdLookup<AccountId, AccountIndex>
where
	AccountId: Codec + Clone + PartialEq + Debug,
	AccountIndex: Codec + Clone + PartialEq + Debug,
	crate::MultiAddress<AccountId, AccountIndex>: Codec + StaticTypeInfo,
{
	type Source = crate::MultiAddress<AccountId, AccountIndex>;
	type Target = AccountId;
	fn lookup(x: Self::Source) -> Result<Self::Target, LookupError> {
		match x {
			crate::MultiAddress::Id(i) => Ok(i),
			_ => Err(LookupError),
		}
	}
	fn unlookup(x: Self::Target) -> Self::Source {
		crate::MultiAddress::Id(x)
	}
}

/// Perform a StaticLookup where there are multiple lookup sources of the same type.
impl<A, B> StaticLookup for (A, B)
where
	A: StaticLookup,
	B: StaticLookup<Source = A::Source, Target = A::Target>,
{
	type Source = A::Source;
	type Target = A::Target;

	fn lookup(x: Self::Source) -> Result<Self::Target, LookupError> {
		A::lookup(x.clone()).or_else(|_| B::lookup(x))
	}
	fn unlookup(x: Self::Target) -> Self::Source {
		A::unlookup(x)
	}
}

/// Extensible conversion trait. Generic over both source and destination types.
/// 可扩展的转换特性。通用的源和目标类型。
pub trait Convert<A, B> {
	/// Make conversion.
	/// 进行转换
	fn convert(a: A) -> B;
}

impl<A, B: Default> Convert<A, B> for () {
	fn convert(_: A) -> B {
		Default::default()
	}
}

/// A structure that performs identity conversion.
/// 执行身份转换的结构。
pub struct Identity;
impl<T> Convert<T, T> for Identity {
	fn convert(a: T) -> T {
		a
	}
}

/// A structure that performs standard conversion using the standard Rust conversion traits.
/// 使用标准 Rust 转换特征执行标准转换的结构。
pub struct ConvertInto;
impl<A, B: From<A>> Convert<A, B> for ConvertInto {
	fn convert(a: A) -> B {
		a.into()
	}
}

/// Convenience type to work around the highly unergonomic syntax needed
/// to invoke the functions of overloaded generic traits, in this case
/// `TryFrom` and `TryInto`.
/// 便利类型，用于解决调用重载泛型特征的功能所需的极不符合人体工程学的语法，在这里是指`TryFrom`和`TryInto`。
pub trait CheckedConversion {
	/// Convert from a value of `T` into an equivalent instance of `Option<Self>`.
	/// 从 `T` 的值转换为 `Option<Self>` 的等效实例。
	/// This just uses `TryFrom` internally but with this
	/// variant you can provide the destination type using turbofish syntax
	/// in case Rust happens not to assume the correct type.
	/// 这只是在内部使用 `TryFrom`，但使用此变体，您可以使用 turbofish 语法提供目标类型，以防 Rust 碰巧没有假定正确的类型。
	fn checked_from<T>(t: T) -> Option<Self>
	where
		Self: TryFrom<T>,
	{
		<Self as TryFrom<T>>::try_from(t).ok()
	}
	/// Consume self to return `Some` equivalent value of `Option<T>`.
	/// 使用 self 返回 `Option<T>` 的 `Some` 等效值。
	/// This just uses `TryInto` internally but with this
	/// variant you can provide the destination type using turbofish syntax
	/// in case Rust happens not to assume the correct type.
	/// 这只是在内部使用 `TryInto`，但使用此变体，您可以使用 turbofish 语法提供目标类型，以防 Rust 碰巧没有假定正确的类型。
	fn checked_into<T>(self) -> Option<T>
	where
		Self: TryInto<T>,
	{
		<Self as TryInto<T>>::try_into(self).ok()
	}
}
impl<T: Sized> CheckedConversion for T {}

/// Multiply and divide by a number that isn't necessarily the same type. Basically just the same
/// as `Mul` and `Div` except it can be used for all basic numeric types.
/// 乘以和除以不一定是相同类型的数字。基本上与 `Mul` 和 `Div` 相同，只是它可以用于所有基本的数字类型。
pub trait Scale<Other> {
	/// The output type of the product of `self` and `Other`.
	type Output;

	/// @return the product of `self` and `other`.
	fn mul(self, other: Other) -> Self::Output;

	/// @return the integer division of `self` and `other`.
	fn div(self, other: Other) -> Self::Output;

	/// @return the modulo remainder of `self` and `other`.
	/// @return `self` 和 `other` 的模余数。
	fn rem(self, other: Other) -> Self::Output;
}
macro_rules! impl_scale {
	($self:ty, $other:ty) => {
		impl Scale<$other> for $self {
			type Output = Self;
			fn mul(self, other: $other) -> Self::Output {
				self * (other as Self)
			}
			fn div(self, other: $other) -> Self::Output {
				self / (other as Self)
			}
			fn rem(self, other: $other) -> Self::Output {
				self % (other as Self)
			}
		}
	};
}
impl_scale!(u128, u128);
impl_scale!(u128, u64);
impl_scale!(u128, u32);
impl_scale!(u128, u16);
impl_scale!(u128, u8);
impl_scale!(u64, u64);
impl_scale!(u64, u32);
impl_scale!(u64, u16);
impl_scale!(u64, u8);
impl_scale!(u32, u32);
impl_scale!(u32, u16);
impl_scale!(u32, u8);
impl_scale!(u16, u16);
impl_scale!(u16, u8);
impl_scale!(u8, u8);

/// Trait for things that can be clear (have no bits set). For numeric types, essentially the same
/// as `Zero`.
/// 可以清楚的事物的特征（没有设置位）。对于数字类型，本质上与“零”相同。
pub trait Clear {
	/// True iff no bits are set.
	/// 如果没有设置位，则为真。
	fn is_clear(&self) -> bool;

	/// Return the value of Self that is clear.
	/// 返回清晰的 Self 的值。
	fn clear() -> Self;
}

impl<T: Default + Eq + PartialEq> Clear for T {
	fn is_clear(&self) -> bool {
		*self == Self::clear()
	}
	fn clear() -> Self {
		Default::default()
	}
}

/// A meta trait for all bit ops.
/// 所有位操作的元特征。
pub trait SimpleBitOps:
	Sized
	+ Clear
	+ sp_std::ops::BitOr<Self, Output = Self>
	+ sp_std::ops::BitXor<Self, Output = Self>
	+ sp_std::ops::BitAnd<Self, Output = Self>
{
}
impl<
		T: Sized
			+ Clear
			+ sp_std::ops::BitOr<Self, Output = Self>
			+ sp_std::ops::BitXor<Self, Output = Self>
			+ sp_std::ops::BitAnd<Self, Output = Self>,
	> SimpleBitOps for T
{
}

/// Abstraction around hashing
/// 围绕哈希的抽象
// Stupid bug in the Rust compiler believes derived
// traits must be fulfilled by all type parameters.
// Rust 编译器中的愚蠢错误认为派生特征必须由所有类型参数实现。
pub trait Hash:
	'static
	+ MaybeSerializeDeserialize
	+ Debug
	+ Clone
	+ Eq
	+ PartialEq
	+ Hasher<Out = <Self as Hash>::Output>
{
	/// The hash type produced.
	type Output: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ sp_std::hash::Hash
		+ AsRef<[u8]>
		+ AsMut<[u8]>
		+ Copy
		+ Default
		+ Encode
		+ Decode
		+ MaxEncodedLen
		+ TypeInfo;

	/// Produce the hash of some byte-slice.
	/// 产生一些字节slice的散列。
	fn hash(s: &[u8]) -> Self::Output {
		<Self as Hasher>::hash(s)
	}

	/// Produce the hash of some codec-encodable value.
	/// 产生一些编解码器编码值的散列。
	fn hash_of<S: Encode>(s: &S) -> Self::Output {
		Encode::using_encoded(s, <Self as Hasher>::hash)
	}

	/// The ordered Patricia tree root of the given `input`.
	/// 给定“输入”的有序帕特里夏树根。
	fn ordered_trie_root(input: Vec<Vec<u8>>, state_version: StateVersion) -> Self::Output;

	/// The Patricia tree root of the given mapping.
	/// 给定数组的帕特里夏树
	fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, state_version: StateVersion) -> Self::Output;
}

/// Blake2-256 Hash implementation.
/// Blake2-256 哈希实现。
#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlakeTwo256;

impl Hasher for BlakeTwo256 {
	type Out = sp_core::H256;
	type StdHasher = hash256_std_hasher::Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(s: &[u8]) -> Self::Out {
		sp_io::hashing::blake2_256(s).into()
	}
}

impl Hash for BlakeTwo256 {
	type Output = sp_core::H256;

	fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
		sp_io::trie::blake2_256_root(input, version)
	}

	fn ordered_trie_root(input: Vec<Vec<u8>>, version: StateVersion) -> Self::Output {
		sp_io::trie::blake2_256_ordered_root(input, version)
	}
}

/// Keccak-256 Hash implementation.
/// Keccak-256 hash实现
#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Keccak256;

impl Hasher for Keccak256 {
	type Out = sp_core::H256;
	type StdHasher = hash256_std_hasher::Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(s: &[u8]) -> Self::Out {
		sp_io::hashing::keccak_256(s).into()
	}
}

impl Hash for Keccak256 {
	type Output = sp_core::H256;

	fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
		sp_io::trie::keccak_256_root(input, version)
	}

	fn ordered_trie_root(input: Vec<Vec<u8>>, version: StateVersion) -> Self::Output {
		sp_io::trie::keccak_256_ordered_root(input, version)
	}
}

/// Something that can be checked for equality and printed out to a debug channel if bad.
/// 可以检查是否相等并在错误时打印到调试通道的东西。
pub trait CheckEqual {
	/// Perform the equality check.
	/// 执行相等检查。
	fn check_equal(&self, other: &Self);
}

impl CheckEqual for sp_core::H256 {
	#[cfg(feature = "std")]
	fn check_equal(&self, other: &Self) {
		use sp_core::hexdisplay::HexDisplay;
		if self != other {
			println!(
				"Hash: given={}, expected={}",
				HexDisplay::from(self.as_fixed_bytes()),
				HexDisplay::from(other.as_fixed_bytes()),
			);
		}
	}

	#[cfg(not(feature = "std"))]
	fn check_equal(&self, other: &Self) {
		if self != other {
			"Hash not equal".print();
			self.as_bytes().print();
			other.as_bytes().print();
		}
	}
}

impl CheckEqual for super::generic::DigestItem {
	#[cfg(feature = "std")]
	fn check_equal(&self, other: &Self) {
		if self != other {
			println!("DigestItem: given={:?}, expected={:?}", self, other);
		}
	}

	#[cfg(not(feature = "std"))]
	fn check_equal(&self, other: &Self) {
		if self != other {
			"DigestItem not equal".print();
			(&Encode::encode(self)[..]).print();
			(&Encode::encode(other)[..]).print();
		}
	}
}

sp_core::impl_maybe_marker!(
	/// A type that implements Display when in std environment.
	/// 在 std 环境中实现 Display 的类型。
	trait MaybeDisplay: Display;

	/// A type that implements FromStr when in std environment.
	/// 在 std 环境中实现 FromStr 的类型。
	trait MaybeFromStr: FromStr;

	/// A type that implements Hash when in std environment.
	/// 在 std 环境中实现 Hash 的类型。
	trait MaybeHash: sp_std::hash::Hash;

	/// A type that implements Serialize when in std environment.
	/// 在 std 环境中实现 Serialize 的类型。
	trait MaybeSerialize: Serialize;

	/// A type that implements Serialize, DeserializeOwned and Debug when in std environment.
	/// 在 std 环境中实现 Serialize、DeserializeOwned 和 Debug 的类型。
	trait MaybeSerializeDeserialize: DeserializeOwned, Serialize;

	/// A type that implements MallocSizeOf.
	/// 一种实现 MallocSizeOf 的类型。
	trait MaybeMallocSizeOf: parity_util_mem::MallocSizeOf;
);

/// A type that can be used in runtime structures.
/// 可以在运行时结构中使用的类型。
pub trait Member: Send + Sync + Sized + Debug + Eq + PartialEq + Clone + 'static {}
impl<T: Send + Sync + Sized + Debug + Eq + PartialEq + Clone + 'static> Member for T {}

/// Determine if a `MemberId` is a valid member.
/// 确定 `MemberId` 是否为有效成员。
pub trait IsMember<MemberId> {
	/// Is the given `MemberId` a valid member?
	/// 给定的 `MemberId` 是有效成员吗？
	fn is_member(member_id: &MemberId) -> bool;
}

/// Something which fulfills the abstract idea of a Substrate header. It has types for a `Number`,
/// a `Hash` and a `Hashing`. It provides access to an `extrinsics_root`, `state_root` and
/// `parent_hash`, as well as a `digest` and a block `number`.
/// 满足 Substrate 标头的抽象概念的东西。它具有“数字”、“哈希”和“哈希”的类型。
/// 它提供对“extrinsics_root”、“state_root”和“parent_hash”以及“digest”和“number”块的访问。
/// You can also create a `new` one from those fields.
/// 您还可以从这些字段中创建一个“新”。
pub trait Header:
	Clone + Send + Sync + Codec + Eq + MaybeSerialize + Debug + MaybeMallocSizeOf + 'static
{
	/// Header number.
	/// 区块号。
	type Number: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ sp_std::hash::Hash
		+ Copy
		+ MaybeDisplay
		+ AtLeast32BitUnsigned
		+ Codec
		+ sp_std::str::FromStr
		+ MaybeMallocSizeOf;
	/// Header hash type
	/// 头hash类型
	type Hash: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ sp_std::hash::Hash
		+ Ord
		+ Copy
		+ MaybeDisplay
		+ Default
		+ SimpleBitOps
		+ Codec
		+ AsRef<[u8]>
		+ AsMut<[u8]>
		+ MaybeMallocSizeOf
		+ TypeInfo;
	/// Hashing algorithm
	/// hash算法
	type Hashing: Hash<Output = Self::Hash>;

	/// Creates new header.
	/// 创建一个新的头
	fn new(
		number: Self::Number,
		extrinsics_root: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
	) -> Self;

	/// Returns a reference to the header number.
	/// 返回区块号的引用
	fn number(&self) -> &Self::Number;
	/// Sets the header number.
	/// 设置区块号
	fn set_number(&mut self, number: Self::Number);

	/// Returns a reference to the extrinsics root.
	/// 返回交易根的引用
	fn extrinsics_root(&self) -> &Self::Hash;
	/// Sets the extrinsic root.
	/// 设置交易根
	fn set_extrinsics_root(&mut self, root: Self::Hash);

	/// Returns a reference to the state root.
	/// 返回状态跟的引用
	fn state_root(&self) -> &Self::Hash;
	/// Sets the state root.
	/// 设置状态跟
	fn set_state_root(&mut self, root: Self::Hash);

	/// Returns a reference to the parent hash.
	/// 返回父跟的引用
	fn parent_hash(&self) -> &Self::Hash;
	/// Sets the parent hash.
	/// 设置父跟
	fn set_parent_hash(&mut self, hash: Self::Hash);

	/// Returns a reference to the digest.
	/// 返回摘要的引用
	fn digest(&self) -> &Digest;
	/// Get a mutable reference to the digest.
	/// 获取一个摘要的可变引用
	fn digest_mut(&mut self) -> &mut Digest;

	/// Returns the hash of the header.
	/// 返回头的hash
	fn hash(&self) -> Self::Hash {
		<Self::Hashing as Hash>::hash_of(self)
	}
}

/// Something which fulfills the abstract idea of a Substrate block. It has types for
/// `Extrinsic` pieces of information as well as a `Header`.
/// 满足 Substrate 块的抽象概念的东西。它具有“外部”信息的类型以及“标题”。
/// You can get an iterator over each of the `extrinsics` and retrieve the `header`.
/// 您可以在每个 `extrinsics` 上获取一个迭代器并检索 `header`。
pub trait Block:
	Clone + Send + Sync + Codec + Eq + MaybeSerialize + Debug + MaybeMallocSizeOf + 'static
{
	/// Type for extrinsics.
	/// 交易
	type Extrinsic: Member + Codec + Extrinsic + MaybeSerialize + MaybeMallocSizeOf;
	/// Header type.
	/// 头
	type Header: Header<Hash = Self::Hash> + MaybeMallocSizeOf;
	/// Block hash type.
	/// hash类型
	type Hash: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ sp_std::hash::Hash
		+ Ord
		+ Copy
		+ MaybeDisplay
		+ Default
		+ SimpleBitOps
		+ Codec
		+ AsRef<[u8]>
		+ AsMut<[u8]>
		+ MaybeMallocSizeOf
		+ TypeInfo;

	/// Returns a reference to the header.
	/// 返回头的引用
	fn header(&self) -> &Self::Header;
	/// Returns a reference to the list of extrinsics.
	/// 返回交易的引用列表
	fn extrinsics(&self) -> &[Self::Extrinsic];
	/// Split the block into header and list of extrinsics.
	/// 切分区块位头和交易列表
	fn deconstruct(self) -> (Self::Header, Vec<Self::Extrinsic>);
	/// Creates new block from header and extrinsics.
	/// 使用头和一系列交易创建一个区块
	fn new(header: Self::Header, extrinsics: Vec<Self::Extrinsic>) -> Self;
	/// Returns the hash of the block.
	/// 返回区块的hash
	fn hash(&self) -> Self::Hash {
		<<Self::Header as Header>::Hashing as Hash>::hash_of(self.header())
	}
	/// Creates an encoded block from the given `header` and `extrinsics` without requiring the
	/// creation of an instance.
	/// 从给定的 `header` 和 `extrinsics` 创建一个编码块，而不需要创建实例。
	fn encode_from(header: &Self::Header, extrinsics: &[Self::Extrinsic]) -> Vec<u8>;
}

/// Something that acts like an `Extrinsic`.
/// 交易的行为定义
pub trait Extrinsic: Sized + MaybeMallocSizeOf {
	/// The function call.
	/// 可调用的函数类型
	type Call;

	/// The payload we carry for signed extrinsics.
	/// 我们为已签名的外部数据携带的有效负载。
	/// Usually it will contain a `Signature` and
	/// may include some additional data that are specific to signed
	/// extrinsics.
	/// 通常它会包含一个“签名”，并且可能包含一些特定于已签名外部数据的附加数据。
	type SignaturePayload;

	/// Is this `Extrinsic` signed?
	/// If no information are available about signed/unsigned, `None` should be returned.
	/// 交易是否签名？
	/// 如果没有关于已签名未签名的信息，则应返回“None”。
	fn is_signed(&self) -> Option<bool> {
		None
	}

	/// Create new instance of the extrinsic.
	/// 创建一个交易实例
	/// Extrinsics can be split into:
	/// 1. Inherents (no signature; created by validators during block production)
	/// 2. Unsigned Transactions (no signature; represent "system calls" or other special kinds of
	/// calls) 3. Signed Transactions (with signature; a regular transactions with known origin)
	/// 外部可分为：
	/// 1. 固有（无签名；由验证者在区块生产期间创建）
	/// 2. 未签名交易（无签名；代表“系统调用”或其他特殊类型的调用）
	/// 3. 签名交易（有签名；常规已知来源的交易）
	fn new(_call: Self::Call, _signed_data: Option<Self::SignaturePayload>) -> Option<Self> {
		None
	}
}

/// Implementor is an [`Extrinsic`] and provides metadata about this extrinsic.
/// 实现者是一个 [`Extrinsic`] 并提供有关此交易的元数据。
pub trait ExtrinsicMetadata {
	/// The format version of the `Extrinsic`.
	/// 交易的格式化版本
	/// By format is meant the encoded representation of the `Extrinsic`.
	/// 格式是指“交易”的编码表示。
	const VERSION: u8;

	/// Signed extensions attached to this `Extrinsic`.
	/// 附加到此“交易”的签名扩展。
	type SignedExtensions: SignedExtension;
}

/// Extract the hashing type for a block.
/// 提取块的hash类型。
pub type HashFor<B> = <<B as Block>::Header as Header>::Hashing;
/// Extract the number type for a block.
/// 提取一个块的快号类型
pub type NumberFor<B> = <<B as Block>::Header as Header>::Number;
/// Extract the digest type for a block.

/// A "checkable" piece of information, used by the standard Substrate Executive in order to
/// check the validity of a piece of extrinsic information, usually by verifying the signature.
/// Implement for pieces of information that require some additional context `Context` in order to
/// be checked.
/// 一条“checkable”的信息，由标准 Substrate Executive 用于检查一条交易信息的有效性，通常通过验证签名。对于需要一些额外的上下文`Context`才能被检查的信息片断，实施。
pub trait Checkable<Context>: Sized {
	/// Returned if `check` succeeds.
	type Checked;

	/// Check self, given an instance of Context.
	fn check(self, c: &Context) -> Result<Self::Checked, TransactionValidityError>;
}

/// A "checkable" piece of information, used by the standard Substrate Executive in order to
/// check the validity of a piece of extrinsic information, usually by verifying the signature.
/// Implement for pieces of information that don't require additional context in order to be
/// checked.
/// 跟上面对比，不需要额外的上下文才能检查
pub trait BlindCheckable: Sized {
	/// Returned if `check` succeeds.
	type Checked;

	/// Check self.
	fn check(self) -> Result<Self::Checked, TransactionValidityError>;
}

// Every `BlindCheckable` is also a `StaticCheckable` for arbitrary `Context`.
// 每个 `BlindCheckable` 也是任意`Context` 的`StaticCheckable`。
impl<T: BlindCheckable, Context> Checkable<Context> for T {
	type Checked = <Self as BlindCheckable>::Checked;

	fn check(self, _c: &Context) -> Result<Self::Checked, TransactionValidityError> {
		BlindCheckable::check(self)
	}
}

/// A lazy call (module function and argument values) that can be executed via its `dispatch`
/// method.
/// 可以通过其 `dispatch` 方法执行的惰性调用（模块函数和参数值）。
pub trait Dispatchable {
	/// Every function call from your runtime has an origin, which specifies where the extrinsic was
	/// generated from. In the case of a signed extrinsic (transaction), the origin contains an
	/// identifier for the caller. The origin can be empty in the case of an inherent extrinsic.
	/// 运行时中的每个函数调用都有一个来源，它指定了交易的来源。
	/// 在签名的外部（事务）的情况下，源包含调用者的标识符。在固有交易的情况下，来源可以为空。
	type Origin;
	/// ...
	type Config;
	/// An opaque set of information attached to the transaction. This could be constructed anywhere
	/// down the line in a runtime. The current Substrate runtime uses a struct with the same name
	/// to represent the dispatch class and weight.
	/// 附加到交易的一组不透明信息。这可以在运行时的任何地方构建。当前的 Substrate 运行时使用同名结构来表示调度类和权重。
	type Info;
	/// Additional information that is returned by `dispatch`. Can be used to supply the caller
	/// with information about a `Dispatchable` that is ownly known post dispatch.
	/// `dispatch` 返回的附加信息。可用于向调用者提供有关调度后自己已知的“可调度”的信息。
	type PostInfo: Eq + PartialEq + Clone + Copy + Encode + Decode + Printable;
	/// Actually dispatch this call and return the result of it.
	/// 实际上调度这个调用并返回它的结果。
	fn dispatch(self, origin: Self::Origin) -> crate::DispatchResultWithInfo<Self::PostInfo>;
}

/// Shortcut to reference the `Info` type of a `Dispatchable`.
/// 引用 `Dispatchable` 的 `Info` 类型的快捷方式。
pub type DispatchInfoOf<T> = <T as Dispatchable>::Info;
/// Shortcut to reference the `PostInfo` type of a `Dispatchable`.
/// 引用 `Dispatchable` 的 `PostInfo` 类型的快捷方式。
pub type PostDispatchInfoOf<T> = <T as Dispatchable>::PostInfo;

impl Dispatchable for () {
	type Origin = ();
	type Config = ();
	type Info = ();
	type PostInfo = ();
	fn dispatch(self, _origin: Self::Origin) -> crate::DispatchResultWithInfo<Self::PostInfo> {
		panic!("This implemention should not be used for actual dispatch.");
	}
}

/// Means by which a transaction may be extended. This type embodies both the data and the logic
/// that should be additionally associated with the transaction. It should be plain old data.
/// 可以扩展交易的方式。这种类型体现了应该与事务额外关联的数据和逻辑。它应该是普通的旧数据。
pub trait SignedExtension:
	Codec + Debug + Sync + Send + Clone + Eq + PartialEq + StaticTypeInfo
{
	/// Unique identifier of this signed extension.
	/// 此签名扩展的唯一标识符。
	/// This will be exposed in the metadata to identify the signed extension used
	/// in an extrinsic.
	/// 这将在元数据中公开，以识别外部使用的签名扩展。
	const IDENTIFIER: &'static str;

	/// The type which encodes the sender identity.
	/// 编码发件人身份的类型。
	type AccountId;

	/// The type which encodes the call to be dispatched.
	/// 编码要分派的调用的类型。
	type Call: Dispatchable;

	/// Any additional data that will go into the signed payload. This may be created dynamically
	/// from the transaction using the `additional_signed` function.
	/// 将进入签名有效负载的任何其他数据。这可以使用 `additional_signed` 函数从交易中动态创建。
	type AdditionalSigned: Encode + TypeInfo;

	/// The type that encodes information that can be passed from pre_dispatch to post-dispatch.
	/// 编码可以从 pre_dispatch 传递到 post-dispatch 的信息的类型。
	type Pre;

	/// Construct any additional data that should be in the signed payload of the transaction. Can
	/// also perform any pre-signature-verification checks and return an error if needed.
	/// 构造应在交易的签名有效负载中的任何其他数据。还可以执行任何预签名验证检查并在需要时返回错误。
	fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError>;

	/// Validate a signed transaction for the transaction queue.
	/// 验证交易队列的签名交易。
	/// This function can be called frequently by the transaction queue,
	/// to obtain transaction validity against current state.
	/// It should perform all checks that determine a valid transaction,
	/// that can pay for its execution and quickly eliminate ones
	/// that are stale or incorrect.
	/// 事务队列可以频繁调用此函数，以获得针对当前状态的事务有效性。它应该执行所有确定有效交易的检查，可以为其执行付费并快速消除过时或不正确的交易。
	/// Make sure to perform the same checks in `pre_dispatch` function.
	/// 确保在 `pre_dispatch` 函数中执行相同的检查。
	fn validate(
		&self,
		_who: &Self::AccountId,
		_call: &Self::Call,
		_info: &DispatchInfoOf<Self::Call>,
		_len: usize,
	) -> TransactionValidity {
		Ok(ValidTransaction::default())
	}

	/// Do any pre-flight stuff for a signed transaction.
	/// 为签署的交易做任何预先的检查。
	/// Note this function by default delegates to `validate`, so that
	/// all checks performed for the transaction queue are also performed during
	/// the dispatch phase (applying the extrinsic).
	/// 请注意，此函数默认委托给 `validate`，因此对事务队列执行的所有检查也在调度阶段执行（应用外部）。
	/// If you ever override this function, you need to make sure to always
	/// perform the same validation as in `validate`.
	/// 如果您曾经重写此函数，则需要确保始终执行与 `validate` 中相同的验证。
	fn pre_dispatch(
		self,
		who: &Self::AccountId,
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError>;

	/// Validate an unsigned transaction for the transaction queue.
	/// 验证事务队列的未签名事务。
	/// This function can be called frequently by the transaction queue
	/// to obtain transaction validity against current state.
	/// It should perform all checks that determine a valid unsigned transaction,
	/// and quickly eliminate ones that are stale or incorrect.
	/// 事务队列可以频繁调用此函数，以获得针对当前状态的事务有效性。它应该执行所有确定有效未签名交易的检查，并快速消除陈旧或不正确的交易。
	/// Make sure to perform the same checks in `pre_dispatch_unsigned` function.
	/// 确保在 `pre_dispatch_unsigned` 函数中执行相同的检查。
	fn validate_unsigned(
		_call: &Self::Call,
		_info: &DispatchInfoOf<Self::Call>,
		_len: usize,
	) -> TransactionValidity {
		Ok(ValidTransaction::default())
	}

	/// Do any pre-flight stuff for a unsigned transaction.
	/// 为未签名的交易做任何预检查
	/// Note this function by default delegates to `validate_unsigned`, so that
	/// all checks performed for the transaction queue are also performed during
	/// the dispatch phase (applying the extrinsic).
	/// 请注意，此函数默认委托给 `validate_unsigned`，因此对事务队列执行的所有检查也在调度阶段执行（应用外部）。
	/// If you ever override this function, you need to make sure to always
	/// perform the same validation as in `validate_unsigned`.
	/// 如果您曾经重写此函数，则需要确保始终执行与 `validate_unsigned` 中相同的验证。
	fn pre_dispatch_unsigned(
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> Result<(), TransactionValidityError> {
		Self::validate_unsigned(call, info, len).map(|_| ()).map_err(Into::into)
	}

	/// Do any post-flight stuff for an extrinsic.
	/// 为外在做任何执行后的处理。
	/// If the transaction is signed, then `_pre` will contain the output of `pre_dispatch`,
	/// and `None` otherwise.
	/// 如果交易已签名，则`_pre`将包含`pre_dispatch`的输出，否则为`None`。
	/// This gets given the `DispatchResult` `_result` from the extrinsic and can, if desired,
	/// introduce a `TransactionValidityError`, causing the block to become invalid for including
	/// it.
	/// 这会从外部获得 `DispatchResult` `_result`，如果需要，可以引入 `TransactionValidityError`，导致块因包含它而变得无效。
	/// WARNING: It is dangerous to return an error here. To do so will fundamentally invalidate the
	/// transaction and any block that it is included in, causing the block author to not be
	/// compensated for their work in validating the transaction or producing the block so far.
	/// 警告：在这里返回错误是危险的。这样做将从根本上使交易及其包含的任何区块无效，导致区块作者迄今为止在验证交易或生成区块方面的工作没有得到补偿。
	/// It can only be used safely when you *know* that the extrinsic is one that can only be
	/// introduced by the current block author; generally this implies that it is an inherent and
	/// will come from either an offchain-worker or via `InherentData`.
	/// 只有知道extrinsic是只有当前区块作者才能引入的，才能放心使用；通常，这意味着它是固有的，将来自链下工作者或通过“InherentData”。
	fn post_dispatch(
		_pre: Option<Self::Pre>,
		_info: &DispatchInfoOf<Self::Call>,
		_post_info: &PostDispatchInfoOf<Self::Call>,
		_len: usize,
		_result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		Ok(())
	}

	/// Returns the metadata for this signed extension.
	/// 返回此签名扩展的元数据。
	/// As a [`SignedExtension`] can be a tuple of [`SignedExtension`]s we need to return a `Vec`
	/// that holds the metadata of each one. Each individual `SignedExtension` must return
	/// *exactly* one [`SignedExtensionMetadata`].
	/// 由于 [`SignedExtension`] 可以是 [`SignedExtension`]s 的元组，我们需要返回包含每个元数据的 `Vec`。
	/// 每个单独的`SignedExtension` 必须准确返回一个[`SignedExtensionMetadata`]。
	/// This method provides a default implementation that returns a vec containing a single
	/// [`SignedExtensionMetadata`].
	/// 此方法提供了一个默认实现，该实现返回一个包含单个 [`SignedExtensionMetadata`] 的 vec。
	fn metadata() -> Vec<SignedExtensionMetadata> {
		sp_std::vec![SignedExtensionMetadata {
			identifier: Self::IDENTIFIER,
			ty: scale_info::meta_type::<Self>(),
			additional_signed: scale_info::meta_type::<Self::AdditionalSigned>()
		}]
	}
}

/// Information about a [`SignedExtension`] for the runtime metadata.
/// 有关运行时元数据的 [`SignedExtension`] 的信息。
pub struct SignedExtensionMetadata {
	/// The unique identifier of the [`SignedExtension`].
	/// 唯一标识符
	pub identifier: &'static str,
	/// The type of the [`SignedExtension`].
	/// 类型
	pub ty: MetaType,
	/// The type of the [`SignedExtension`] additional signed data for the payload.
	/// 附加的签名的数据
	pub additional_signed: MetaType,
}

#[impl_for_tuples(1, 12)]
impl<AccountId, Call: Dispatchable> SignedExtension for Tuple {
	for_tuples!( where #( Tuple: SignedExtension<AccountId=AccountId, Call=Call,> )* );
	type AccountId = AccountId;
	type Call = Call;
	const IDENTIFIER: &'static str = "You should call `identifier()`!";
	for_tuples!( type AdditionalSigned = ( #( Tuple::AdditionalSigned ),* ); );
	for_tuples!( type Pre = ( #( Tuple::Pre ),* ); );

	fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
		Ok(for_tuples!( ( #( Tuple.additional_signed()? ),* ) ))
	}

	fn validate(
		&self,
		who: &Self::AccountId,
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> TransactionValidity {
		let valid = ValidTransaction::default();
		for_tuples!( #( let valid = valid.combine_with(Tuple.validate(who, call, info, len)?); )* );
		Ok(valid)
	}

	fn pre_dispatch(
		self,
		who: &Self::AccountId,
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		Ok(for_tuples!( ( #( Tuple.pre_dispatch(who, call, info, len)? ),* ) ))
	}

	fn validate_unsigned(
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> TransactionValidity {
		let valid = ValidTransaction::default();
		for_tuples!( #( let valid = valid.combine_with(Tuple::validate_unsigned(call, info, len)?); )* );
		Ok(valid)
	}

	fn pre_dispatch_unsigned(
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> Result<(), TransactionValidityError> {
		for_tuples!( #( Tuple::pre_dispatch_unsigned(call, info, len)?; )* );
		Ok(())
	}

	fn post_dispatch(
		pre: Option<Self::Pre>,
		info: &DispatchInfoOf<Self::Call>,
		post_info: &PostDispatchInfoOf<Self::Call>,
		len: usize,
		result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		match pre {
			Some(x) => {
				for_tuples!( #( Tuple::post_dispatch(Some(x.Tuple), info, post_info, len, result)?; )* );
			},
			None => {
				for_tuples!( #( Tuple::post_dispatch(None, info, post_info, len, result)?; )* );
			},
		}
		Ok(())
	}

	fn metadata() -> Vec<SignedExtensionMetadata> {
		let mut ids = Vec::new();
		for_tuples!( #( ids.extend(Tuple::metadata()); )* );
		ids
	}
}

/// Only for bare bone testing when you don't care about signed extensions at all.
#[cfg(feature = "std")]
impl SignedExtension for () {
	type AccountId = u64;
	type AdditionalSigned = ();
	type Call = ();
	type Pre = ();
	const IDENTIFIER: &'static str = "UnitSignedExtension";
	fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> {
		Ok(())
	}
	fn pre_dispatch(
		self,
		who: &Self::AccountId,
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		self.validate(who, call, info, len).map(|_| ())
	}
}

/// An "executable" piece of information, used by the standard Substrate Executive in order to
/// enact a piece of extrinsic information by marshalling and dispatching to a named function
/// call.
///	一条“可执行”信息，由标准 Substrate 执行程序使用，以便通过编组和分派到命名函数调用来制定一条外部信息。
/// Also provides information on to whom this information is attributable and an index that allows
/// each piece of attributable information to be disambiguated.
/// 还提供了有关此信息归属于谁的信息，以及允许消除每条归属信息的歧义的索引。
pub trait Applyable: Sized + Send + Sync {
	/// Type by which we can dispatch. Restricts the `UnsignedValidator` type.
	/// 我们可以发送的类型。限制 `UnsignedValidator` 类型。
	type Call: Dispatchable;

	/// Checks to see if this is a valid *transaction*. It returns information on it if so.
	/// 检查这是否是一个有效的交易。如果是这样，它会返回有关它的信息。
	fn validate<V: ValidateUnsigned<Call = Self::Call>>(
		&self,
		source: TransactionSource,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> TransactionValidity;

	/// Executes all necessary logic needed prior to dispatch and deconstructs into function call,
	/// index and sender.
	/// 在调度和解构为函数调用、索引和发送者之前执行所有必要的逻辑。
	fn apply<V: ValidateUnsigned<Call = Self::Call>>(
		self,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> crate::ApplyExtrinsicResultWithInfo<PostDispatchInfoOf<Self::Call>>;
}

/// A marker trait for something that knows the type of the runtime block.
/// 运行时区块类型的标记特征。
pub trait GetRuntimeBlockType {
	/// The `RuntimeBlock` type.
	/// `RuntimeBlock`类型
	type RuntimeBlock: self::Block;
}

/// A marker trait for something that knows the type of the node block.
/// 节点区块类型的标记特征。
pub trait GetNodeBlockType {
	/// The `NodeBlock` type.
	/// `NodeBlock`类型
	type NodeBlock: self::Block;
}

/// Something that can validate unsigned extrinsics for the transaction pool.
/// 可以验证交易池的未签名交易的东西。
/// Note that any checks done here are only used for determining the validity of
/// the transaction for the transaction pool.
/// 请注意，此处所做的任何检查仅用于确定交易池中交易的有效性。
/// During block execution phase one need to perform the same checks anyway,
/// since this function is not being called.
/// 在块执行阶段，无论如何都需要执行相同的检查，因为没有调用此函数。
pub trait ValidateUnsigned {
	/// The call to validate
	/// 验证调用的对象（函数）
	type Call;

	/// Validate the call right before dispatch.
	/// 在调度之前验证。
	/// This method should be used to prevent transactions already in the pool
	/// (i.e. passing `validate_unsigned`) from being included in blocks
	/// in case we know they now became invalid.
	/// 这个方法应该用来防止已经在池中的事务（即传递`validate_unsigned`）被包含在块中，以使我们知道它们现在变得无效。
	/// By default it's a good idea to call `validate_unsigned` from within
	/// this function again to make sure we never include an invalid transaction.
	/// 默认情况下，最好在此函数中再次调用 `validate_unsigned` 以确保我们永远不会包含无效交易。
	/// Changes made to storage WILL be persisted if the call returns `Ok`.
	/// 如果调用返回“Ok”，对存储所做的更改将被保留。
	fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
		Self::validate_unsigned(TransactionSource::InBlock, call)
			.map(|_| ())
			.map_err(Into::into)
	}

	/// Return the validity of the call
	/// 返回调用的有效性
	/// This doesn't execute any side-effects; it merely checks
	/// whether the transaction would panic if it were included or not.
	/// 这不会执行任何副作用；它只是检查如果交易被包含或不包含，它是否会恐慌。
	/// Changes made to storage should be discarded by caller.
	/// 调用者应丢弃对存储所做的更改。
	fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity;
}

/// Opaque data type that may be destructured into a series of raw byte slices (which represent
/// individual keys).
/// 可以分解为一系列原始字节切片（代表单个键）的不透明数据类型。
pub trait OpaqueKeys: Clone {
	/// Types bound to this opaque keys that provide the key type ids returned.
	/// 绑定到此不透明键的类型，提供返回的键类型 ID。
	type KeyTypeIdProviders;

	/// Return the key-type IDs supported by this set.
	/// 返回此集合支持的键类型 ID。
	fn key_ids() -> &'static [crate::KeyTypeId];
	/// Get the raw bytes of key with key-type ID `i`.
	/// 获取密钥类型 ID 为“i”的密钥的原始字节。
	fn get_raw(&self, i: super::KeyTypeId) -> &[u8];
	/// Get the decoded key with key-type ID `i`.
	/// 获取密钥类型 ID 为“i”的解码密钥。
	fn get<T: Decode>(&self, i: super::KeyTypeId) -> Option<T> {
		T::decode(&mut self.get_raw(i)).ok()
	}
	/// Verify a proof of ownership for the keys.
	/// 验证密钥的所有权证明。
	fn ownership_proof_is_valid(&self, _proof: &[u8]) -> bool {
		true
	}
}

/// Input that adds infinite number of zero after wrapped input.
/// 在包装输入后添加无限个零的输入。
/// This can add an infinite stream of zeros onto any input, not just a slice as with
/// `TrailingZerosInput`.
/// 这可以将无限的零流添加到任何输入上，而不仅仅是像 `TrailingZerosInput` 的切片。
pub struct AppendZerosInput<'a, T>(&'a mut T);

impl<'a, T> AppendZerosInput<'a, T> {
	/// Create a new instance from the given byte array.
	pub fn new(input: &'a mut T) -> Self {
		Self(input)
	}
}

impl<'a, T: codec::Input> codec::Input for AppendZerosInput<'a, T> {
	fn remaining_len(&mut self) -> Result<Option<usize>, codec::Error> {
		Ok(None)
	}

	fn read(&mut self, into: &mut [u8]) -> Result<(), codec::Error> {
		let remaining = self.0.remaining_len()?;
		let completed = if let Some(n) = remaining {
			let readable = into.len().min(n);
			// this should never fail if `remaining_len` API is implemented correctly.
			self.0.read(&mut into[..readable])?;
			readable
		} else {
			// Fill it byte-by-byte.
			let mut i = 0;
			while i < into.len() {
				if let Ok(b) = self.0.read_byte() {
					into[i] = b;
					i += 1;
				} else {
					break
				}
			}
			i
		};
		// Fill the rest with zeros.
		for i in &mut into[completed..] {
			*i = 0;
		}
		Ok(())
	}
}

/// Input that adds infinite number of zero after wrapped input.
/// 在包装输入后添加无限个零的输入。
pub struct TrailingZeroInput<'a>(&'a [u8]);

impl<'a> TrailingZeroInput<'a> {
	/// Create a new instance from the given byte array.
	pub fn new(data: &'a [u8]) -> Self {
		Self(data)
	}

	/// Create a new instance which only contains zeroes as input.
	pub fn zeroes() -> Self {
		Self::new(&[][..])
	}
}

impl<'a> codec::Input for TrailingZeroInput<'a> {
	fn remaining_len(&mut self) -> Result<Option<usize>, codec::Error> {
		Ok(None)
	}

	fn read(&mut self, into: &mut [u8]) -> Result<(), codec::Error> {
		let len_from_inner = into.len().min(self.0.len());
		into[..len_from_inner].copy_from_slice(&self.0[..len_from_inner]);
		for i in &mut into[len_from_inner..] {
			*i = 0;
		}
		self.0 = &self.0[len_from_inner..];

		Ok(())
	}
}

/// This type can be converted into and possibly from an AccountId (which itself is generic).
/// 这种类型可以转换为并且可能来自 AccountId（它本身是通用的）。
pub trait AccountIdConversion<AccountId>: Sized {
	/// Convert into an account ID. This is infallible.
	/// 转换为账户id，万无一失（肯定成功）
	fn into_account(&self) -> AccountId {
		self.into_sub_account(&())
	}

	/// Try to convert an account ID into this type. Might not succeed.
	/// 尝试将帐户 ID 转换为这种类型。可能不会成功。
	fn try_from_account(a: &AccountId) -> Option<Self> {
		Self::try_from_sub_account::<()>(a).map(|x| x.0)
	}

	/// Convert this value amalgamated with the a secondary "sub" value into an account ID. This is
	/// infallible.
	/// 将此值与辅助“子”值合并为帐户 ID。这是万无一失的。
	/// NOTE: The account IDs from this and from `into_account` are *not* guaranteed to be distinct
	/// for any given value of `self`, nor are different invocations to this with different types
	/// `T`. For example, the following will all encode to the same account ID value:
	/// - `self.into_sub_account(0u32)`
	/// - `self.into_sub_account(vec![0u8; 0])`
	/// - `self.into_account()`
	/// 注意：对于任何给定的 `self` 值，来自 this 和来自 `into_account` 的帐户 ID 不能保证是不同的，对于不同类型的 `T` 的不同调用也不保证。
	/// 例如，以下将全部编码为相同的帐户 ID 值：
	/// - `self.into_sub_account(0u32)`
	/// - `self.into_sub_account(vec![0u8; 0])`
	/// - `self.into_account()`
	fn into_sub_account<S: Encode>(&self, sub: S) -> AccountId;

	/// Try to convert an account ID into this type. Might not succeed.
	/// 尝试将帐户 ID 转换为这种类型。可能不会成功。
	fn try_from_sub_account<S: Decode>(x: &AccountId) -> Option<(Self, S)>;
}

/// Format is TYPE_ID ++ encode(parachain ID) ++ 00.... where 00... is indefinite trailing zeroes to
/// fill AccountId.
/// 格式为 TYPE_ID ++ encode(parachain ID) ++ 00.... 其中 00... 是用于填充 AccountId 的不定尾随零。
impl<T: Encode + Decode, Id: Encode + Decode + TypeId> AccountIdConversion<T> for Id {
	fn into_sub_account<S: Encode>(&self, sub: S) -> T {
		(Id::TYPE_ID, self, sub)
			.using_encoded(|b| T::decode(&mut TrailingZeroInput(b)))
			.expect("`AccountId` type is never greater than 32 bytes; qed")
	}

	fn try_from_sub_account<S: Decode>(x: &T) -> Option<(Self, S)> {
		x.using_encoded(|d| {
			if &d[0..4] != Id::TYPE_ID {
				return None
			}
			let mut cursor = &d[4..];
			let result = Decode::decode(&mut cursor).ok()?;
			if cursor.iter().all(|x| *x == 0) {
				Some(result)
			} else {
				None
			}
		})
	}
}

/// Calls a given macro a number of times with a set of fixed params and an incrementing numeral.
/// 使用一组固定参数和递增数字多次调用给定宏。
/// e.g.
/// ```nocompile
/// count!(println ("{}",) foo, bar, baz);
/// // Will result in three `println!`s: "0", "1" and "2".
/// ```
#[macro_export]
macro_rules! count {
	($f:ident ($($x:tt)*) ) => ();
	($f:ident ($($x:tt)*) $x1:tt) => { $f!($($x)* 0); };
	($f:ident ($($x:tt)*) $x1:tt, $x2:tt) => { $f!($($x)* 0); $f!($($x)* 1); };
	($f:ident ($($x:tt)*) $x1:tt, $x2:tt, $x3:tt) => { $f!($($x)* 0); $f!($($x)* 1); $f!($($x)* 2); };
	($f:ident ($($x:tt)*) $x1:tt, $x2:tt, $x3:tt, $x4:tt) => {
		$f!($($x)* 0); $f!($($x)* 1); $f!($($x)* 2); $f!($($x)* 3);
	};
	($f:ident ($($x:tt)*) $x1:tt, $x2:tt, $x3:tt, $x4:tt, $x5:tt) => {
		$f!($($x)* 0); $f!($($x)* 1); $f!($($x)* 2); $f!($($x)* 3); $f!($($x)* 4);
	};
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_opaque_keys_inner {
	(
		$( #[ $attr:meta ] )*
		pub struct $name:ident {
			$(
				$( #[ $inner_attr:meta ] )*
				pub $field:ident: $type:ty,
			)*
		}
	) => {
		$( #[ $attr ] )*
		#[derive(
			Clone, PartialEq, Eq,
			$crate::codec::Encode,
			$crate::codec::Decode,
			$crate::scale_info::TypeInfo,
			$crate::RuntimeDebug,
		)]
		pub struct $name {
			$(
				$( #[ $inner_attr ] )*
				pub $field: <$type as $crate::BoundToRuntimeAppPublic>::Public,
			)*
		}

		impl $name {
			/// Generate a set of keys with optionally using the given seed.
			/// 可选地使用给定的种子生成一组密钥。
			/// The generated key pairs are stored in the keystore.
			/// 生成的密钥对存储在密钥库中。
			/// Returns the concatenated SCALE encoded public keys.
			/// 返回串联的 SCALE 编码的公钥。
			pub fn generate(seed: Option<$crate::sp_std::vec::Vec<u8>>) -> $crate::sp_std::vec::Vec<u8> {
				let keys = Self{
					$(
						$field: <
							<
								$type as $crate::BoundToRuntimeAppPublic
							>::Public as $crate::RuntimeAppPublic
						>::generate_pair(seed.clone()),
					)*
				};
				$crate::codec::Encode::encode(&keys)
			}

			/// Converts `Self` into a `Vec` of `(raw public key, KeyTypeId)`.
			pub fn into_raw_public_keys(
				self,
			) -> $crate::sp_std::vec::Vec<($crate::sp_std::vec::Vec<u8>, $crate::KeyTypeId)> {
				let mut keys = Vec::new();
				$(
					keys.push((
						$crate::RuntimeAppPublic::to_raw_vec(&self.$field),
						<
							<
								$type as $crate::BoundToRuntimeAppPublic
							>::Public as $crate::RuntimeAppPublic
						>::ID,
					));
				)*

				keys
			}

			/// Decode `Self` from the given `encoded` slice and convert `Self` into the raw public
			/// keys (see [`Self::into_raw_public_keys`]).
			///
			/// Returns `None` when the decoding failed, otherwise `Some(_)`.
			pub fn decode_into_raw_public_keys(
				encoded: &[u8],
			) -> Option<$crate::sp_std::vec::Vec<($crate::sp_std::vec::Vec<u8>, $crate::KeyTypeId)>> {
				<Self as $crate::codec::Decode>::decode(&mut &encoded[..])
					.ok()
					.map(|s| s.into_raw_public_keys())
			}
		}

		impl $crate::traits::OpaqueKeys for $name {
			type KeyTypeIdProviders = ( $( $type, )* );

			fn key_ids() -> &'static [$crate::KeyTypeId] {
				&[
					$(
						<
							<
								$type as $crate::BoundToRuntimeAppPublic
							>::Public as $crate::RuntimeAppPublic
						>::ID
					),*
				]
			}

			fn get_raw(&self, i: $crate::KeyTypeId) -> &[u8] {
				match i {
					$(
						i if i == <
							<
								$type as $crate::BoundToRuntimeAppPublic
							>::Public as $crate::RuntimeAppPublic
						>::ID =>
							self.$field.as_ref(),
					)*
					_ => &[],
				}
			}
		}
	};
}

/// Implement `OpaqueKeys` for a described struct.
///
/// Every field type must implement [`BoundToRuntimeAppPublic`](crate::BoundToRuntimeAppPublic).
/// `KeyTypeIdProviders` is set to the types given as fields.
///
/// ```rust
/// use sp_runtime::{
/// 	impl_opaque_keys, KeyTypeId, BoundToRuntimeAppPublic, app_crypto::{sr25519, ed25519}
/// };
///
/// pub struct KeyModule;
/// impl BoundToRuntimeAppPublic for KeyModule { type Public = ed25519::AppPublic; }
///
/// pub struct KeyModule2;
/// impl BoundToRuntimeAppPublic for KeyModule2 { type Public = sr25519::AppPublic; }
///
/// impl_opaque_keys! {
/// 	pub struct Keys {
/// 		pub key_module: KeyModule,
/// 		pub key_module2: KeyModule2,
/// 	}
/// }
/// ```
#[macro_export]
#[cfg(feature = "std")]
macro_rules! impl_opaque_keys {
	{
		$( #[ $attr:meta ] )*
		pub struct $name:ident {
			$(
				$( #[ $inner_attr:meta ] )*
				pub $field:ident: $type:ty,
			)*
		}
	} => {
		$crate::paste::paste! {
			use $crate::serde as [< __opaque_keys_serde_import__ $name >];

			$crate::impl_opaque_keys_inner! {
				$( #[ $attr ] )*
				#[derive($crate::serde::Serialize, $crate::serde::Deserialize)]
				#[serde(crate = "__opaque_keys_serde_import__" $name)]
				pub struct $name {
					$(
						$( #[ $inner_attr ] )*
						pub $field: $type,
					)*
				}
			}
		}
	}
}

#[macro_export]
#[cfg(not(feature = "std"))]
#[doc(hidden)]
macro_rules! impl_opaque_keys {
	{
		$( #[ $attr:meta ] )*
		pub struct $name:ident {
			$(
				$( #[ $inner_attr:meta ] )*
				pub $field:ident: $type:ty,
			)*
		}
	} => {
		$crate::impl_opaque_keys_inner! {
			$( #[ $attr ] )*
			pub struct $name {
				$(
					$( #[ $inner_attr ] )*
					pub $field: $type,
				)*
			}
		}
	}
}

/// Trait for things which can be printed from the runtime.
pub trait Printable {
	/// Print the object.
	fn print(&self);
}

impl<T: Printable> Printable for &T {
	fn print(&self) {
		(*self).print()
	}
}

impl Printable for u8 {
	fn print(&self) {
		(*self as u64).print()
	}
}

impl Printable for u32 {
	fn print(&self) {
		(*self as u64).print()
	}
}

impl Printable for usize {
	fn print(&self) {
		(*self as u64).print()
	}
}

impl Printable for u64 {
	fn print(&self) {
		sp_io::misc::print_num(*self);
	}
}

impl Printable for &[u8] {
	fn print(&self) {
		sp_io::misc::print_hex(self);
	}
}

impl Printable for &str {
	fn print(&self) {
		sp_io::misc::print_utf8(self.as_bytes());
	}
}

impl Printable for bool {
	fn print(&self) {
		if *self {
			"true".print()
		} else {
			"false".print()
		}
	}
}

impl Printable for () {
	fn print(&self) {
		"()".print()
	}
}

#[impl_for_tuples(1, 12)]
impl Printable for Tuple {
	fn print(&self) {
		for_tuples!( #( Tuple.print(); )* )
	}
}

/// Something that can convert a [`BlockId`](crate::generic::BlockId) to a number or a hash.
/// 可以将 [`BlockId`](crate::generic::BlockId) 转换为数字或哈希的东西。
#[cfg(feature = "std")]
pub trait BlockIdTo<Block: self::Block> {
	/// The error type that will be returned by the functions.
	/// 函数将返回的错误类型。
	type Error: std::error::Error;

	/// Convert the given `block_id` to the corresponding block hash.
	/// 将给定的 `block_id` 转换为相应的块哈希。
	fn to_hash(
		&self,
		block_id: &crate::generic::BlockId<Block>,
	) -> Result<Option<Block::Hash>, Self::Error>;

	/// Convert the given `block_id` to the corresponding block number.
	/// 将给定的 `block_id` 转换为相应的块号。
	fn to_number(
		&self,
		block_id: &crate::generic::BlockId<Block>,
	) -> Result<Option<NumberFor<Block>>, Self::Error>;
}

/// Get current block number
/// 获取当前区块号
pub trait BlockNumberProvider {
	/// Type of `BlockNumber` to provide.
	/// 提供的“BlockNumber”类型。
	type BlockNumber: Codec + Clone + Ord + Eq + AtLeast32BitUnsigned;

	/// Returns the current block number.
	/// 返回当前区块号
	/// Provides an abstraction over an arbitrary way of providing the
	/// current block number.
	/// 提供对提供当前块号的任意方式的抽象。
	/// In case of using crate `sp_runtime` with the crate `frame-system`,
	/// 如果将 crate `sp_runtime` 与 crate `frame-system` 一起使用，
	/// it is already implemented for
	/// `frame_system::Pallet<T: Config>` as:
	///
	/// ```ignore
	/// fn current_block_number() -> Self {
	///     frame_system::Pallet<Config>::block_number()
	/// }
	/// ```
	/// .
	fn current_block_number() -> Self::BlockNumber;

	/// Utility function only to be used in benchmarking scenarios, to be implemented optionally,
	/// else a noop.
	///
	/// It allows for setting the block number that will later be fetched
	/// This is useful in case the block number provider is different than System
	#[cfg(feature = "runtime-benchmarks")]
	fn set_block_number(_block: Self::BlockNumber) {}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::codec::{Decode, Encode, Input};
	use sp_core::{
		crypto::{Pair, UncheckedFrom},
		ecdsa,
	};

	mod t {
		use sp_application_crypto::{app_crypto, sr25519};
		use sp_core::crypto::KeyTypeId;
		app_crypto!(sr25519, KeyTypeId(*b"test"));
	}

	#[test]
	fn app_verify_works() {
		use super::AppVerify;
		use t::*;

		let s = Signature::try_from(vec![0; 64]).unwrap();
		let _ = s.verify(&[0u8; 100][..], &Public::unchecked_from([0; 32]));
	}

	#[derive(Encode, Decode, Default, PartialEq, Debug)]
	struct U32Value(u32);
	impl super::TypeId for U32Value {
		const TYPE_ID: [u8; 4] = [0x0d, 0xf0, 0xfe, 0xca];
	}
	// cafef00d

	#[derive(Encode, Decode, Default, PartialEq, Debug)]
	struct U16Value(u16);
	impl super::TypeId for U16Value {
		const TYPE_ID: [u8; 4] = [0xfe, 0xca, 0x0d, 0xf0];
	}
	// f00dcafe

	type AccountId = u64;

	#[test]
	fn into_account_should_work() {
		let r: AccountId = U32Value::into_account(&U32Value(0xdeadbeef));
		assert_eq!(r, 0x_deadbeef_cafef00d);
	}

	#[test]
	fn try_from_account_should_work() {
		let r = U32Value::try_from_account(&0x_deadbeef_cafef00d_u64);
		assert_eq!(r.unwrap(), U32Value(0xdeadbeef));
	}

	#[test]
	fn into_account_with_fill_should_work() {
		let r: AccountId = U16Value::into_account(&U16Value(0xc0da));
		assert_eq!(r, 0x_0000_c0da_f00dcafe);
	}

	#[test]
	fn try_from_account_with_fill_should_work() {
		let r = U16Value::try_from_account(&0x0000_c0da_f00dcafe_u64);
		assert_eq!(r.unwrap(), U16Value(0xc0da));
	}

	#[test]
	fn bad_try_from_account_should_fail() {
		let r = U16Value::try_from_account(&0x0000_c0de_baadcafe_u64);
		assert!(r.is_none());
		let r = U16Value::try_from_account(&0x0100_c0da_f00dcafe_u64);
		assert!(r.is_none());
	}

	#[test]
	fn trailing_zero_should_work() {
		let mut t = super::TrailingZeroInput(&[1, 2, 3]);
		assert_eq!(t.remaining_len(), Ok(None));
		let mut buffer = [0u8; 2];
		assert_eq!(t.read(&mut buffer), Ok(()));
		assert_eq!(t.remaining_len(), Ok(None));
		assert_eq!(buffer, [1, 2]);
		assert_eq!(t.read(&mut buffer), Ok(()));
		assert_eq!(t.remaining_len(), Ok(None));
		assert_eq!(buffer, [3, 0]);
		assert_eq!(t.read(&mut buffer), Ok(()));
		assert_eq!(t.remaining_len(), Ok(None));
		assert_eq!(buffer, [0, 0]);
	}

	#[test]
	fn ecdsa_verify_works() {
		let msg = &b"test-message"[..];
		let (pair, _) = ecdsa::Pair::generate();

		let signature = pair.sign(&msg);
		assert!(ecdsa::Pair::verify(&signature, msg, &pair.public()));

		assert!(signature.verify(msg, &pair.public()));
		assert!(signature.verify(msg, &pair.public()));
	}
}
