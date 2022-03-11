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

//! Externalities extensions storage.
//! 外部性扩展存储
//! Externalities support to register a wide variety custom extensions. The [`Extensions`] provides
//! some convenience functionality to store and retrieve these extensions.
//! 外部性支持注册各种自定义扩展。 [`Extensions`] 提供一些方便的功能来存储和检索这些扩展。
//! It is required that each extension implements the [`Extension`] trait.
//! 每个扩展都需要实现 [`Extension`] 特征。

use crate::Error;
use sp_std::{
	any::{Any, TypeId},
	boxed::Box,
	collections::btree_map::{BTreeMap, Entry},
	ops::DerefMut,
};

/// Marker trait for types that should be registered as [`Externalities`](crate::Externalities)
/// extension.
/// 应该注册为 [`Externalities`](crate::Externalities) 扩展的类型的标记特征。
/// As extensions are stored as `Box<Any>`, this trait should give more confidence that the correct
/// type is registered and requested.
/// 由于扩展存储为 `Box<Any>`，因此该 trait 应该更加确信注册和请求了正确的类型。
pub trait Extension: Send + Any {
	/// Return the extension as `&mut dyn Any`.
	/// 将扩展名返回为 `&mut dyn Any`。
	/// This is a trick to make the trait type castable into an `Any`.
	/// 这是使 trait 类型可转换为 `Any` 的技巧。
	fn as_mut_any(&mut self) -> &mut dyn Any;
}

/// Macro for declaring an extension that usable with [`Extensions`].
/// 用于声明可与 [`Extensions`] 一起使用的扩展的宏。
/// The extension will be an unit wrapper struct that implements [`Extension`], `Deref` and
/// `DerefMut`. The wrapped type is given by the user.
/// 扩展将是一个单元包装结构，它实现了 [`Extension`]、`Deref` 和 `DerefMut`。包装类型由用户给出。
/// # Example
/// ```
/// # use sp_externalities::decl_extension;
/// decl_extension! {
///     /// Some test extension
///     struct TestExt(String);
/// }
/// ```
#[macro_export]
macro_rules! decl_extension {
	(
		$( #[ $attr:meta ] )*
		$vis:vis struct $ext_name:ident ($inner:ty);
	) => {
		$( #[ $attr ] )*
		$vis struct $ext_name (pub $inner);

		impl $crate::Extension for $ext_name {
			fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
				self
			}
		}

		impl std::ops::Deref for $ext_name {
			type Target = $inner;

			fn deref(&self) -> &Self::Target {
				&self.0
			}
		}

		impl std::ops::DerefMut for $ext_name {
			fn deref_mut(&mut self) -> &mut Self::Target {
				&mut self.0
			}
		}

		impl From<$inner> for $ext_name {
			fn from(inner: $inner) -> Self {
				Self(inner)
			}
 		}
	}
}

/// Something that provides access to the [`Extensions`] store.
/// 提供访问 [`Extensions`] 存储的东西。
/// This is a super trait of the [`Externalities`](crate::Externalities).
/// 这是 [`Externalities`](crate::Externalities) 的一个父特征。
pub trait ExtensionStore {
	/// Tries to find a registered extension by the given `type_id` and returns it as a `&mut dyn
	/// Any`.
	/// 尝试通过给定的 `type_id` 查找已注册的扩展并将其作为 `&mut dyn Any` 返回。
	/// It is advised to use [`ExternalitiesExt::extension`](crate::ExternalitiesExt::extension)
	/// instead of this function to get type system support and automatic type downcasting.
	/// 建议使用 [`ExternalitiesExt::extension`](crate::ExternalitiesExt::extension) 代替此函数来获得类型系统支持和自动类型向下转换。
	fn extension_by_type_id(&mut self, type_id: TypeId) -> Option<&mut dyn Any>;

	/// Register extension `extension` with specified `type_id`.
	/// 使用指定的`type_id`注册扩展`extension`。
	/// It should return error if extension is already registered.
	fn register_extension_with_type_id(
		&mut self,
		type_id: TypeId,
		extension: Box<dyn Extension>,
	) -> Result<(), Error>;

	/// Deregister extension with speicifed 'type_id' and drop it.
	/// 使用指定的“type_id”取消注册扩展并将其删除。
	/// It should return error if extension is not registered.
	fn deregister_extension_by_type_id(&mut self, type_id: TypeId) -> Result<(), Error>;
}

/// Stores extensions that should be made available through the externalities.
/// 存储应该通过外部性提供的扩展。
#[derive(Default)]
pub struct Extensions {
	extensions: BTreeMap<TypeId, Box<dyn Extension>>,
}

#[cfg(feature = "std")]
impl std::fmt::Debug for Extensions {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Extensions: ({})", self.extensions.len())
	}
}

impl Extensions {
	/// Create new instance of `Self`.
	pub fn new() -> Self {
		Self::default()
	}

	/// Register the given extension.
	pub fn register<E: Extension>(&mut self, ext: E) {
		let type_id = ext.type_id();
		self.extensions.insert(type_id, Box::new(ext));
	}

	/// Register extension `extension` using the given `type_id`.
	pub fn register_with_type_id(
		&mut self,
		type_id: TypeId,
		extension: Box<dyn Extension>,
	) -> Result<(), Error> {
		match self.extensions.entry(type_id) {
			Entry::Vacant(vacant) => {
				vacant.insert(extension);
				Ok(())
			},
			Entry::Occupied(_) => Err(Error::ExtensionAlreadyRegistered),
		}
	}

	/// Return a mutable reference to the requested extension.
	/// 返回对请求的扩展的可变引用。
	pub fn get_mut(&mut self, ext_type_id: TypeId) -> Option<&mut dyn Any> {
		self.extensions
			.get_mut(&ext_type_id)
			.map(DerefMut::deref_mut)
			.map(Extension::as_mut_any)
	}

	/// Deregister extension for the given `type_id`.
	/// 取消注册给定 `type_id` 的扩展名。
	/// Returns `true` when the extension was registered.
	pub fn deregister(&mut self, type_id: TypeId) -> bool {
		self.extensions.remove(&type_id).is_some()
	}

	/// Returns a mutable iterator over all extensions.
	pub fn iter_mut<'a>(
		&'a mut self,
	) -> impl Iterator<Item = (&'a TypeId, &'a mut Box<dyn Extension>)> {
		self.extensions.iter_mut()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	decl_extension! {
		struct DummyExt(u32);
	}
	decl_extension! {
		struct DummyExt2(u32);
	}

	#[test]
	fn register_and_retrieve_extension() {
		let mut exts = Extensions::new();
		exts.register(DummyExt(1));
		exts.register(DummyExt2(2));

		let ext = exts.get_mut(TypeId::of::<DummyExt>()).expect("Extension is registered");
		let ext_ty = ext.downcast_mut::<DummyExt>().expect("Downcasting works");

		assert_eq!(ext_ty.0, 1);
	}
}
