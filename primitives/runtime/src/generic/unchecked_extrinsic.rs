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

//! Generic implementation of an unchecked (pre-verification) extrinsic.
//! 未检查（预验证）交易的通用实现。

use crate::{
	generic::CheckedExtrinsic,
	traits::{
		self, Checkable, Extrinsic, ExtrinsicMetadata, IdentifyAccount, MaybeDisplay, Member,
		SignedExtension,
	},
	transaction_validity::{InvalidTransaction, TransactionValidityError},
	OpaqueExtrinsic,
};
use codec::{Compact, Decode, Encode, EncodeLike, Error, Input};
use scale_info::{build::Fields, meta_type, Path, StaticTypeInfo, Type, TypeInfo, TypeParameter};
use sp_io::hashing::blake2_256;
use sp_std::{fmt, prelude::*};

/// Current version of the [`UncheckedExtrinsic`] encoded format.
/// [`UncheckedExtrinsic`] 编码格式的当前版本。
/// This version needs to be bumped if the encoded representation changes.
/// It ensures that if the representation is changed and the format is not known,
/// the decoding fails.
/// 如果编码表示发生变化，则需要更改此版本。它确保如果表示更改并且格式未知，则解码失败。
const EXTRINSIC_FORMAT_VERSION: u8 = 4;

/// A extrinsic right from the external world. This is unchecked and so
/// can contain a signature.
/// 来自外部世界的外在权利。这是未选中的，因此可以包含签名。
#[derive(PartialEq, Eq, Clone)]
pub struct UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension,
{
	/// The signature, address, number of extrinsics have come before from
	/// the same signer and an era describing the longevity of this transaction,
	/// if this is a signed extrinsic.
	/// 签名、地址、外部数据的数量来自同一签名者和描述此交易寿命的时代（如果这是已签名的外部数据）。
	pub signature: Option<(Address, Signature, Extra)>,
	/// The function that should be called.
	pub function: Call,
}

/// Manual [`TypeInfo`] implementation because of custom encoding. The data is a valid encoded
/// `Vec<u8>`, but requires some logic to extract the signature and payload.
/// 由于自定义编码，手动 [`TypeInfo`] 实现。数据是一个有效的编码 `Vec<u8>`，但需要一些逻辑来提取签名和有效负载。
/// See [`UncheckedExtrinsic::encode`] and [`UncheckedExtrinsic::decode`].
/// 请参阅 [`UncheckedExtrinsic::encode`] 和 [`UncheckedExtrinsic::decode`]。
impl<Address, Call, Signature, Extra> TypeInfo
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: StaticTypeInfo,
	Call: StaticTypeInfo,
	Signature: StaticTypeInfo,
	Extra: SignedExtension + StaticTypeInfo,
{
	type Identity = UncheckedExtrinsic<Address, Call, Signature, Extra>;

	fn type_info() -> Type {
		Type::builder()
			.path(Path::new("UncheckedExtrinsic", module_path!()))
			// Include the type parameter types, even though they are not used directly in any of
			// the described fields. These type definitions can be used by downstream consumers
			// to help construct the custom decoding from the opaque bytes (see below).
			// 包括类型参数类型，即使它们没有直接用于任何描述的字段。下游消费者可以使用这些类型定义来帮助从不透明字节构建自定义解码（见下文）
			.type_params(vec![
				TypeParameter::new("Address", Some(meta_type::<Address>())),
				TypeParameter::new("Call", Some(meta_type::<Call>())),
				TypeParameter::new("Signature", Some(meta_type::<Signature>())),
				TypeParameter::new("Extra", Some(meta_type::<Extra>())),
			])
			.docs(&["UncheckedExtrinsic raw bytes, requires custom decoding routine"])
			// Because of the custom encoding, we can only accurately describe the encoding as an
			// opaque `Vec<u8>`. Downstream consumers will need to manually implement the codec to
			// encode/decode the `signature` and `function` fields.
			// 由于自定义编码，我们只能将编码准确描述为不透明的`Vec<u8>`。下游消费者将需要手动实现编解码器来对“签名”和“功能”字段进行编码解码。
			.composite(Fields::unnamed().field(|f| f.ty::<Vec<u8>>()))
	}
}

#[cfg(feature = "std")]
impl<Address, Call, Signature, Extra> parity_util_mem::MallocSizeOf
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension,
{
	fn size_of(&self, _ops: &mut parity_util_mem::MallocSizeOfOps) -> usize {
		// Instantiated only in runtime.
		0
	}
}

impl<Address, Call, Signature, Extra: SignedExtension>
	UncheckedExtrinsic<Address, Call, Signature, Extra>
{
	/// New instance of a signed extrinsic aka "transaction".
	/// 已签名的外部又名“交易”的新实例。
	pub fn new_signed(function: Call, signed: Address, signature: Signature, extra: Extra) -> Self {
		Self { signature: Some((signed, signature, extra)), function }
	}

	/// New instance of an unsigned extrinsic aka "inherent".
	pub fn new_unsigned(function: Call) -> Self {
		Self { signature: None, function }
	}
}

impl<Address, Call, Signature, Extra: SignedExtension> Extrinsic
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
{
	type Call = Call;

	type SignaturePayload = (Address, Signature, Extra);

	fn is_signed(&self) -> Option<bool> {
		Some(self.signature.is_some())
	}

	fn new(function: Call, signed_data: Option<Self::SignaturePayload>) -> Option<Self> {
		Some(if let Some((address, signature, extra)) = signed_data {
			Self::new_signed(function, address, signature, extra)
		} else {
			Self::new_unsigned(function)
		})
	}
}

impl<Address, AccountId, Call, Signature, Extra, Lookup> Checkable<Lookup>
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Member + MaybeDisplay,
	Call: Encode + Member,
	Signature: Member + traits::Verify,
	<Signature as traits::Verify>::Signer: IdentifyAccount<AccountId = AccountId>,
	Extra: SignedExtension<AccountId = AccountId>,
	AccountId: Member + MaybeDisplay,
	Lookup: traits::Lookup<Source = Address, Target = AccountId>,
{
	type Checked = CheckedExtrinsic<AccountId, Call, Extra>;

	fn check(self, lookup: &Lookup) -> Result<Self::Checked, TransactionValidityError> {
		Ok(match self.signature {
			Some((signed, signature, extra)) => {
				let signed = lookup.lookup(signed)?;//从签名获取accountId
				let raw_payload = SignedPayload::new(self.function, extra)?;//构造
				if !raw_payload.using_encoded(|payload| signature.verify(payload, &signed)) {//验证
					return Err(InvalidTransaction::BadProof.into())
				}

				let (function, extra, _) = raw_payload.deconstruct();//解出来
				CheckedExtrinsic { signed: Some((signed, extra)), function }
			},
			None => CheckedExtrinsic { signed: None, function: self.function },
		})
	}
}

impl<Address, Call, Signature, Extra> ExtrinsicMetadata
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension,
{
	const VERSION: u8 = EXTRINSIC_FORMAT_VERSION;
	type SignedExtensions = Extra;
}

/// A payload that has been signed for an unchecked extrinsics.
/// 已为未经检查的外部对象签名的有效负载。
/// Note that the payload that we sign to produce unchecked extrinsic signature
/// is going to be different than the `SignaturePayload` - so the thing the extrinsic
/// actually contains.
/// 请注意，我们为生成未经检查的外部签名而签名的有效负载将与“SignaturePayload”不同 - 所以外部实际包含的东西。
pub struct SignedPayload<Call, Extra: SignedExtension>((Call, Extra, Extra::AdditionalSigned));

impl<Call, Extra> SignedPayload<Call, Extra>
where
	Call: Encode,
	Extra: SignedExtension,
{
	/// Create new `SignedPayload`.
	///
	/// This function may fail if `additional_signed` of `Extra` is not available.
	/// 如果 `Extra` 的 `additional_signed` 不可用，此函数可能会失败。
	pub fn new(call: Call, extra: Extra) -> Result<Self, TransactionValidityError> {
		let additional_signed = extra.additional_signed()?;
		let raw_payload = (call, extra, additional_signed);
		Ok(Self(raw_payload))
	}

	/// Create new `SignedPayload` from raw components.
	/// 从raw组件中创建一个新的`SignedPayload`
	pub fn from_raw(call: Call, extra: Extra, additional_signed: Extra::AdditionalSigned) -> Self {
		Self((call, extra, additional_signed))
	}

	/// Deconstruct the payload into it's components.
	/// 将有效负载解构为它的组件。
	pub fn deconstruct(self) -> (Call, Extra, Extra::AdditionalSigned) {
		self.0
	}
}

impl<Call, Extra> Encode for SignedPayload<Call, Extra>
where
	Call: Encode,
	Extra: SignedExtension,
{
	/// Get an encoded version of this payload.
	/// 获取此有效负载的编码版本。
	/// Payloads longer than 256 bytes are going to be `blake2_256`-hashed.
	/// 超过 256 字节的有效负载将被 `blake2_256`-hashed。
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		self.0.using_encoded(|payload| {
			if payload.len() > 256 {
				f(&blake2_256(payload)[..])
			} else {
				f(payload)
			}
		})
	}
}

impl<Call, Extra> EncodeLike for SignedPayload<Call, Extra>
where
	Call: Encode,
	Extra: SignedExtension,
{
}

impl<Address, Call, Signature, Extra> Decode for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Decode,
	Signature: Decode,
	Call: Decode,
	Extra: SignedExtension,
{
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		// This is a little more complicated than usual since the binary format must be compatible
		// with SCALE's generic `Vec<u8>` type. Basically this just means accepting that there
		// will be a prefix of vector length.
		// 这比平常稍微复杂一点，因为二进制格式必须与 SCALE 的通用 `Vec<u8>` 类型兼容。基本上这只是意味着接受会有一个向量长度的前缀。
		let expected_length: Compact<u32> = Decode::decode(input)?;
		let before_length = input.remaining_len()?;

		let version = input.read_byte()?;

		let is_signed = version & 0b1000_0000 != 0;
		let version = version & 0b0111_1111;
		if version != EXTRINSIC_FORMAT_VERSION {
			return Err("Invalid transaction version".into())
		}

		let signature = is_signed.then(|| Decode::decode(input)).transpose()?;
		let function = Decode::decode(input)?;

		if let Some((before_length, after_length)) =
			input.remaining_len()?.and_then(|a| before_length.map(|b| (b, a)))
		{
			let length = before_length.saturating_sub(after_length);

			if length != expected_length.0 as usize {
				return Err("Invalid length prefix".into())
			}
		}

		Ok(Self { signature, function })
	}
}

impl<Address, Call, Signature, Extra> Encode for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Encode,
	Signature: Encode,
	Call: Encode,
	Extra: SignedExtension,
{
	fn encode(&self) -> Vec<u8> {
		let mut tmp = Vec::with_capacity(sp_std::mem::size_of::<Self>());

		// 1 byte version id.
		// decode的时候，这里做了对应的处理
		match self.signature.as_ref() {
			Some(s) => {
				tmp.push(EXTRINSIC_FORMAT_VERSION | 0b1000_0000);
				s.encode_to(&mut tmp);
			},
			None => {
				tmp.push(EXTRINSIC_FORMAT_VERSION & 0b0111_1111);
			},
		}
		self.function.encode_to(&mut tmp);

		let compact_len = codec::Compact::<u32>(tmp.len() as u32);

		// Allocate the output buffer with the correct length
		let mut output = Vec::with_capacity(compact_len.size_hint() + tmp.len());

		compact_len.encode_to(&mut output);
		output.extend(tmp);

		output
	}
}

impl<Address, Call, Signature, Extra> EncodeLike
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Encode,
	Signature: Encode,
	Call: Encode,
	Extra: SignedExtension,
{
}

#[cfg(feature = "std")]
impl<Address: Encode, Signature: Encode, Call: Encode, Extra: SignedExtension> serde::Serialize
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
{
	fn serialize<S>(&self, seq: S) -> Result<S::Ok, S::Error>
	where
		S: ::serde::Serializer,
	{
		self.using_encoded(|bytes| seq.serialize_bytes(bytes))
	}
}

#[cfg(feature = "std")]
impl<'a, Address: Decode, Signature: Decode, Call: Decode, Extra: SignedExtension>
	serde::Deserialize<'a> for UncheckedExtrinsic<Address, Call, Signature, Extra>
{
	fn deserialize<D>(de: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'a>,
	{
		let r = sp_core::bytes::deserialize(de)?;
		Decode::decode(&mut &r[..])
			.map_err(|e| serde::de::Error::custom(format!("Decode error: {}", e)))
	}
}

impl<Address, Call, Signature, Extra> fmt::Debug
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: fmt::Debug,
	Call: fmt::Debug,
	Extra: SignedExtension,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"UncheckedExtrinsic({:?}, {:?})",
			self.signature.as_ref().map(|x| (&x.0, &x.2)),
			self.function,
		)
	}
}

impl<Address, Call, Signature, Extra> From<UncheckedExtrinsic<Address, Call, Signature, Extra>>
	for OpaqueExtrinsic
where
	Address: Encode,
	Signature: Encode,
	Call: Encode,
	Extra: SignedExtension,
{
	fn from(extrinsic: UncheckedExtrinsic<Address, Call, Signature, Extra>) -> Self {
		Self::from_bytes(extrinsic.encode().as_slice()).expect(
			"both OpaqueExtrinsic and UncheckedExtrinsic have encoding that is compatible with \
				raw Vec<u8> encoding; qed",
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		codec::{Decode, Encode},
		testing::TestSignature as TestSig,
		traits::{DispatchInfoOf, IdentityLookup, SignedExtension},
	};
	use sp_io::hashing::blake2_256;

	type TestContext = IdentityLookup<u64>;
	type TestAccountId = u64;
	type TestCall = Vec<u8>;

	const TEST_ACCOUNT: TestAccountId = 0;

	// NOTE: this is demonstration. One can simply use `()` for testing.
	#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd, TypeInfo)]
	struct TestExtra;
	impl SignedExtension for TestExtra {
		const IDENTIFIER: &'static str = "TestExtra";
		type AccountId = u64;
		type Call = ();
		type AdditionalSigned = ();
		type Pre = ();

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

	type Ex = UncheckedExtrinsic<TestAccountId, TestCall, TestSig, TestExtra>;
	type CEx = CheckedExtrinsic<TestAccountId, TestCall, TestExtra>;

	#[test]
	fn unsigned_codec_should_work() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		let encoded = ux.encode();
		assert_eq!(Ex::decode(&mut &encoded[..]), Ok(ux));
	}

	#[test]
	fn invalid_length_prefix_is_detected() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		let mut encoded = ux.encode();

		let length = Compact::<u32>::decode(&mut &encoded[..]).unwrap();
		Compact(length.0 + 10).encode_to(&mut &mut encoded[..1]);

		assert_eq!(Ex::decode(&mut &encoded[..]), Err("Invalid length prefix".into()));
	}

	#[test]
	fn signed_codec_should_work() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(TEST_ACCOUNT, (vec![0u8; 0], TestExtra).encode()),
			TestExtra,
		);
		let encoded = ux.encode();
		assert_eq!(Ex::decode(&mut &encoded[..]), Ok(ux));
	}

	#[test]
	fn large_signed_codec_should_work() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(
				TEST_ACCOUNT,
				(vec![0u8; 257], TestExtra).using_encoded(blake2_256)[..].to_owned(),
			),
			TestExtra,
		);
		let encoded = ux.encode();
		assert_eq!(Ex::decode(&mut &encoded[..]), Ok(ux));
	}

	#[test]
	fn unsigned_check_should_work() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		assert!(!ux.is_signed().unwrap_or(false));
		assert!(<Ex as Checkable<TestContext>>::check(ux, &Default::default()).is_ok());
	}

	#[test]
	fn badly_signed_check_should_fail() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(TEST_ACCOUNT, vec![0u8; 0]),
			TestExtra,
		);
		assert!(ux.is_signed().unwrap_or(false));
		assert_eq!(
			<Ex as Checkable<TestContext>>::check(ux, &Default::default()),
			Err(InvalidTransaction::BadProof.into()),
		);
	}

	#[test]
	fn signed_check_should_work() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(TEST_ACCOUNT, (vec![0u8; 0], TestExtra).encode()),
			TestExtra,
		);
		assert!(ux.is_signed().unwrap_or(false));
		assert_eq!(
			<Ex as Checkable<TestContext>>::check(ux, &Default::default()),
			Ok(CEx { signed: Some((TEST_ACCOUNT, TestExtra)), function: vec![0u8; 0] }),
		);
	}

	#[test]
	fn encoding_matches_vec() {
		let ex = Ex::new_unsigned(vec![0u8; 0]);
		let encoded = ex.encode();
		let decoded = Ex::decode(&mut encoded.as_slice()).unwrap();
		assert_eq!(decoded, ex);
		let as_vec: Vec<u8> = Decode::decode(&mut encoded.as_slice()).unwrap();
		assert_eq!(as_vec.encode(), encoded);
	}

	#[test]
	fn conversion_to_opaque() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		let encoded = ux.encode();
		let opaque: OpaqueExtrinsic = ux.into();
		let opaque_encoded = opaque.encode();
		assert_eq!(opaque_encoded, encoded);
	}

	#[test]
	fn large_bad_prefix_should_work() {
		let encoded = Compact::<u32>::from(u32::MAX).encode();
		assert_eq!(
			Ex::decode(&mut &encoded[..]),
			Err(Error::from("Not enough data to fill buffer"))
		);
	}
}
