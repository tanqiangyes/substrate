// This file is part of Substrate.

// Copyright (C) 2018-2022 Parity Technologies (UK) Ltd.
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

//! This crate provides means to instantiate and execute wasm modules.
//! 这个 crate 提供了实例化和执行 wasm 模块的方法。
//! It works even when the user of this library executes from
//! inside the wasm VM. In this case the same VM is used for execution
//! of both the sandbox owner and the sandboxed module, without compromising security
//! and without the performance penalty of full wasm emulation inside wasm.
//! 即使这个库的用户从wasm虚拟机内执行，它也能工作。
//! 在这种情况下，同一台虚拟机被用于执行沙盒所有者和沙盒模块，不会影响安全性，也不会因为在wasm内部进行完全的wasm仿真而导致性能下降。
//! This is achieved by using bindings to the wasm VM, which are published by the host API.
//! This API is thin and consists of only a handful functions. It contains functions for
//! instantiating modules and executing them, but doesn't contain functions for inspecting the
//! module structure. The user of this library is supposed to read the wasm module.
//! 这是通过使用wasm虚拟机的绑定来实现的，这些绑定是由主机API发布的。
//! 这个API很薄，只由少数几个函数组成。它包含实例化模块和执行模块的函数，但不包含检查模块结构的函数。这个库的用户应该阅读wasm模块。
//! When this crate is used in the `std` environment all these functions are implemented by directly
//! calling the wasm VM.
//! 当这个crate在`std`环境中使用时，所有这些函数都是通过直接调用wasm VM来实现的。
//! Examples of possible use-cases for this library are not limited to the following:
//!
//! - implementing smart-contract runtimes that use wasm for contract code
//! - executing a wasm substrate runtime inside of a wasm parachain
//! 这个库的可能使用情况的例子不限于以下几个方面。
// - 实现智能合约运行系统，使用wasm进行合约编码
// - 在wasm parachain中执行wasm底层运行时

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use sp_std::prelude::*;

pub use sp_core::sandbox::HostError;
pub use sp_wasm_interface::{ReturnValue, Value};

/// The target used for logging.
const TARGET: &str = "runtime::sandbox";

pub mod embedded_executor;
#[cfg(not(feature = "std"))]
pub mod host_executor;

#[cfg(all(feature = "wasmer-sandbox", not(feature = "std")))]
pub use host_executor as default_executor;

#[cfg(not(all(feature = "wasmer-sandbox", not(feature = "std"))))]
pub use embedded_executor as default_executor;

/// Error that can occur while using this crate.
#[derive(sp_core::RuntimeDebug)]
pub enum Error {
	/// Module is not valid, couldn't be instantiated.
	Module,

	/// Access to a memory or table was made with an address or an index which is out of bounds.
	/// 使用超出范围的地址或索引访问内存或表。
	/// Note that if wasm module makes an out-of-bounds access then trap will occur.
	/// 请注意，如果 wasm 模块进行越界访问，则会发生陷阱。
	OutOfBounds,

	/// Failed to invoke the start function or an exported function for some reason.
	/// 由于某种原因未能调用启动函数或导出的函数。
	Execution,
}

impl From<Error> for HostError {
	fn from(_e: Error) -> HostError {
		HostError
	}
}

/// Function pointer for specifying functions by the
/// supervisor in [`EnvironmentDefinitionBuilder`].
/// [`EnvironmentDefinitionBuilder`] 中主管指定函数的函数指针。
/// [`EnvironmentDefinitionBuilder`]: struct.EnvironmentDefinitionBuilder.html
pub type HostFuncType<T> = fn(&mut T, &[Value]) -> Result<ReturnValue, HostError>;

/// Reference to a sandboxed linear memory, that
/// will be used by the guest module.
/// 对客户模块将使用的沙盒线性内存的引用。
/// The memory can't be directly accessed by supervisor, but only
/// through designated functions [`get`](SandboxMemory::get) and [`set`](SandboxMemory::set).
/// 内存不能被supervisor直接访问，只能通过指定函数[`get`](SandboxMemory::get)和[`set`](SandboxMemory::set)。
pub trait SandboxMemory: Sized + Clone {
	/// Construct a new linear memory instance.
	/// 构造一个新的线性内存实例。
	/// The memory allocated with initial number of pages specified by `initial`.
	/// Minimal possible value for `initial` is 0 and maximum possible is `65536`.
	/// (Since maximum addressable memory is 2<sup>32</sup> = 4GiB = 65536 * 64KiB).
	/// 分配有由`initial`指定的初始页数的内存。 `initial` 的最小可能值为 0，最大可能值为 `65536`。
	/// （因为最大可寻址内存为 2<sup>32<sup> = 4GiB = 65536 64KiB）。
	/// It is possible to limit maximum number of pages this memory instance can have by specifying
	/// `maximum`. If not specified, this memory instance would be able to allocate up to 4GiB.
	/// 可以通过指定 `maximum` 来限制此内存实例可以拥有的最大页数。如果未指定，此内存实例最多可以分配 4GiB。
	/// Allocated memory is always zeroed.
	/// 分配的内存总是归零。
	fn new(initial: u32, maximum: Option<u32>) -> Result<Self, Error>;

	/// Read a memory area at the address `ptr` with the size of the provided slice `buf`.
	/// 使用提供的切片 `buf` 的大小读取地址 `ptr` 处的内存区域。
	/// Returns `Err` if the range is out-of-bounds.
	/// 如果范围超出范围，则返回 `Err`。
	fn get(&self, ptr: u32, buf: &mut [u8]) -> Result<(), Error>;

	/// Write a memory area at the address `ptr` with contents of the provided slice `buf`.
	/// 在地址 `ptr` 处写入一个内存区域，其中包含提供的 slice `buf` 的内容。
	/// Returns `Err` if the range is out-of-bounds.
	/// 如果范围超出范围，则返回 `Err`。
	fn set(&self, ptr: u32, value: &[u8]) -> Result<(), Error>;
}

/// Struct that can be used for defining an environment for a sandboxed module.
/// 可用于为沙盒模块定义环境的结构。
/// The sandboxed module can access only the entities which were defined and passed
/// to the module at the instantiation time.
/// 沙盒模块只能访问在实例化时定义并传递给模块的实体。
pub trait SandboxEnvironmentBuilder<State, Memory>: Sized {
	/// Construct a new `EnvironmentDefinitionBuilder`.
	fn new() -> Self;

	/// Register a host function in this environment definition.
	/// 在此环境定义中注册一个主机函数。
	/// NOTE that there is no constraints on type of this function. An instance
	/// can import function passed here with any signature it wants. It can even import
	/// the same function (i.e. with same `module` and `field`) several times. It's up to
	/// the user code to check or constrain the types of signatures.
	/// 请注意，此函数的类型没有限制。实例可以使用它想要的任何签名导入此处传递的函数。
	/// 它甚至可以多次导入相同的函数（即具有相同的“模块”和“字段”）。由用户代码来检查或限制签名的类型。
	fn add_host_func<N1, N2>(&mut self, module: N1, field: N2, f: HostFuncType<State>)
	where
		N1: Into<Vec<u8>>,
		N2: Into<Vec<u8>>;

	/// Register a memory in this environment definition.
	/// 在此环境定义中注册内存。
	fn add_memory<N1, N2>(&mut self, module: N1, field: N2, mem: Memory)
	where
		N1: Into<Vec<u8>>,
		N2: Into<Vec<u8>>;
}

/// Sandboxed instance of a wasm module.
/// wasm 模块的沙盒实例。
/// This instance can be used for invoking exported functions.
/// 此实例可用于调用导出的函数。
pub trait SandboxInstance<State>: Sized {
	/// The memory type used for this sandbox.
	/// 用于此沙盒的内存类型。
	type Memory: SandboxMemory;

	/// The environment builder used to construct this sandbox.
	/// 用于构建此沙箱的环境构建器。
	type EnvironmentBuilder: SandboxEnvironmentBuilder<State, Self::Memory>;

	/// Instantiate a module with the given [`EnvironmentDefinitionBuilder`]. It will
	/// run the `start` function (if it is present in the module) with the given `state`.
	/// 使用给定的 [`EnvironmentDefinitionBuilder`] 实例化一个模块。它将使用给定的 `state` 运行 `start` 函数（如果它存在于模块中）。
	/// Returns `Err(Error::Module)` if this module can't be instantiated with the given
	/// environment. If execution of `start` function generated a trap, then `Err(Error::Execution)`
	/// will be returned.
	/// 如果无法使用给定环境实例化此模块，则返回 `Err(Error::Module)`。
	/// 如果 `start` 函数的执行产生了一个陷阱，则 `Err(Error::Execution)` 将被返回。
	/// [`EnvironmentDefinitionBuilder`]: struct.EnvironmentDefinitionBuilder.html
	fn new(
		code: &[u8],
		env_def_builder: &Self::EnvironmentBuilder,
		state: &mut State,
	) -> Result<Self, Error>;

	/// Invoke an exported function with the given name.
	/// 调用具有给定名称的导出函数。
	/// # Errors
	///
	/// Returns `Err(Error::Execution)` if:
	/// 返回`Err(Error::Execution)`：
	/// - An export function name isn't a proper utf8 byte sequence,
	/// - This module doesn't have an exported function with the given name,
	/// - If types of the arguments passed to the function doesn't match function signature then
	///   trap occurs (as if the exported function was called via call_indirect),
	/// - Trap occurred at the execution time.
	/// - 导出函数名称不是正确的 utf8 字节序列，
	/// - 此模块没有具有给定名称的导出函数，
	/// - 如果传递给函数的参数类型与函数签名不匹配，则发生陷阱（如如果导出的函数是通过 call_indirect 调用的），
	/// - 陷阱发生在执行时。
	fn invoke(
		&mut self,
		name: &str,
		args: &[Value],
		state: &mut State,
	) -> Result<ReturnValue, Error>;

	/// Get the value from a global with the given `name`.
	/// 从具有给定“名称”的全局变量中获取值。
	/// Returns `Some(_)` if the global could be found.
	/// 如果可以找到全局，则返回 `Some(_)`。
	fn get_global_val(&self, name: &str) -> Option<Value>;
}
