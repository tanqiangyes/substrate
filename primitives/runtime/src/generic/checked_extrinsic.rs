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

//! Generic implementation of an extrinsic that has passed the verification
//! stage.
//! 已通过验证阶段的外在因素的通用实现。。

use crate::{
	traits::{
		self, DispatchInfoOf, Dispatchable, MaybeDisplay, Member, PostDispatchInfoOf,
		SignedExtension, ValidateUnsigned,
	},
	transaction_validity::{TransactionSource, TransactionValidity},
};

/// Definition of something that the external world might want to say; its
/// existence implies that it has been checked and is good, particularly with
/// regards to the signature.
/// 外部世界可能想说的话的定义；它的存在意味着它已经过检查并且是好的，特别是在签名方面。
#[derive(PartialEq, Eq, Clone, sp_core::RuntimeDebug)]
pub struct CheckedExtrinsic<AccountId, Call, Extra> {
	/// Who this purports to be from and the number of extrinsics have come before
	/// from the same signer, if anyone (note this is not a signature).
	/// 这声称来自谁以及外部的数量来自同一签名者（如果有人的话）（注意这不是签名）。
	pub signed: Option<(AccountId, Extra)>,

	/// The function that should be called.
	pub function: Call,
}

impl<AccountId, Call, Extra, Origin> traits::Applyable for CheckedExtrinsic<AccountId, Call, Extra>
where
	AccountId: Member + MaybeDisplay,
	Call: Member + Dispatchable<Origin = Origin>,
	Extra: SignedExtension<AccountId = AccountId, Call = Call>,
	Origin: From<Option<AccountId>>,
{
	type Call = Call;

	fn validate<U: ValidateUnsigned<Call = Self::Call>>(
		&self,
		// TODO [#5006;ToDr] should source be passed to `SignedExtension`s?
		// Perhaps a change for 2.0 to avoid breaking too much APIs?
		source: TransactionSource,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> TransactionValidity {
		if let Some((ref id, ref extra)) = self.signed {
			//已经签名过了，因此直接进行验证
			Extra::validate(extra, id, &self.function, info, len)
		} else {
			//没有签名
			let valid = Extra::validate_unsigned(&self.function, info, len)?;
			let unsigned_validation = U::validate_unsigned(source, &self.function)?;
			Ok(valid.combine_with(unsigned_validation))
		}
	}

	fn apply<U: ValidateUnsigned<Call = Self::Call>>(
		self,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> crate::ApplyExtrinsicResultWithInfo<PostDispatchInfoOf<Self::Call>> {
		let (maybe_who, maybe_pre) = if let Some((id, extra)) = self.signed {
			//已经签名，进行预先处理，返回相应的处理结果
			let pre = Extra::pre_dispatch(extra, &id, &self.function, info, len)?;
			(Some(id), Some(pre))
		} else {
			//预先处理，未签名的交易，
			Extra::pre_dispatch_unsigned(&self.function, info, len)?;
			//在处理之前进行预处理
			U::pre_dispatch(&self.function)?;
			(None, None)
		};
		//实际上调度这个调用并返回它的结果。
		let res = self.function.dispatch(Origin::from(maybe_who));
		let post_info = match res {
			Ok(info) => info,
			Err(err) => err.post_info,
		};
		//进行额外的信息的处理
		Extra::post_dispatch(
			maybe_pre,
			info,
			&post_info,
			len,
			&res.map(|_| ()).map_err(|e| e.error),
		)?;
		Ok(res)
	}
}
