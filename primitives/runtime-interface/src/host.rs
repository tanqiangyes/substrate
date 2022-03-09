// This file is part of Substrate.

// Copyright (C) 2019-2022 Parity Technologies (UK) Ltd.
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

//! Traits required by the runtime interface from the host side.
//! 主机端运行时接口所需的特征

use crate::RIType;

use sp_wasm_interface::{FunctionContext, Result};

/// Something that can be converted into a ffi value.
/// 可以转换为 ffi 值的东西。
pub trait IntoFFIValue: RIType {
	/// Convert `self` into a ffi value.
	/// 将'self'转换为一个ffi值
	fn into_ffi_value(self, context: &mut dyn FunctionContext) -> Result<Self::FFIType>;
}

/// Something that can be converted into a preallocated ffi value.
/// 可以转换为预先分配的 ffi 值的东西。
/// Every type parameter that should be given as `&mut` into a runtime interface function, needs
/// to implement this trait. After executing the host implementation of the runtime interface
/// function, the value is copied into the preallocated wasm memory.
/// 每个应该作为 `&mut` 提供给运行时接口函数的类型参数都需要实现此 trait。在执行运行时接口函数的主机实现后，该值被复制到预先分配的 wasm 内存中。
/// This should only be used for types which have a fixed size, like slices. Other types like a vec
/// do not work with this interface, as we can not call into wasm to reallocate memory. So, this
/// trait should be implemented carefully.
/// 这应该只用于具有固定大小的类型，如切片。其他类型如 vec 不适用于此接口，因为我们无法调用 wasm 来重新分配内存。因此，应谨慎实施此特征。
pub trait IntoPreallocatedFFIValue: RIType {
	/// As `Self` can be an unsized type, it needs to be represented by a sized type at the host.
	/// This `SelfInstance` is the sized type.
	/// 由于 `Self` 可以是无大小的类型，它需要在主机上用一个有大小的类型来表示。这个 `SelfInstance` 是大小的类型。
	type SelfInstance;

	/// Convert `self_instance` into the given preallocated ffi value.
	/// 将 `self_instance` 转换为给定的预分配 ffi 值。
	fn into_preallocated_ffi_value(
		self_instance: Self::SelfInstance,
		context: &mut dyn FunctionContext,
		allocated: Self::FFIType,
	) -> Result<()>;
}

/// Something that can be created from a ffi value.
/// Implementations are safe to assume that the `arg` given to `from_ffi_value`
/// is only generated by the corresponding [`wasm::IntoFFIValue`](crate::wasm::IntoFFIValue)
/// implementation.
/// 可以从 ffi 值创建的东西。
/// 实现可以安全地假设给予 `from_ffi_value` 的 `arg` 仅由相应的 [`wasm::IntoFFIValue`](crate::wasm::IntoFFIValue) 实现生成。
pub trait FromFFIValue: RIType {
	/// As `Self` can be an unsized type, it needs to be represented by a sized type at the host.
	/// This `SelfInstance` is the sized type.
	type SelfInstance;

	/// Create `SelfInstance` from the given
	fn from_ffi_value(
		context: &mut dyn FunctionContext,
		arg: Self::FFIType,
	) -> Result<Self::SelfInstance>;
}
