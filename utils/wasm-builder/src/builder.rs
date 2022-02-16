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

use std::{
	env,
	path::{Path, PathBuf},
	process,
};

/// Returns the manifest dir from the `CARGO_MANIFEST_DIR` env.
fn get_manifest_dir() -> PathBuf {
	env::var("CARGO_MANIFEST_DIR")
		.expect("`CARGO_MANIFEST_DIR` is always set for `build.rs` files; qed")
		.into()
}

/// First step of the [`WasmBuilder`] to select the project to build.
pub struct WasmBuilderSelectProject {
	/// This parameter just exists to make it impossible to construct
	/// this type outside of this crate.
	/// 这个参数的存在是为了使它不可能在这个 crate 之外构造这个类型。
	_ignore: (),
}

impl WasmBuilderSelectProject {
	/// Use the current project as project for building the WASM binary.
	/// 使用当前项目作为构建 WASM 二进制文件的项目。
	/// # Panics
	///
	/// Panics if the `CARGO_MANIFEST_DIR` variable is not set. This variable
	/// is always set by `Cargo` in `build.rs` files.
	pub fn with_current_project(self) -> WasmBuilder {
		WasmBuilder {
			rust_flags: Vec::new(),
			file_name: None,
			project_cargo_toml: get_manifest_dir().join("Cargo.toml"),
			features_to_enable: Vec::new(),
		}
	}

	/// Use the given `path` as project for building the WASM binary.
	/// 使用给定的“路径”作为构建 WASM 二进制文件的项目。
	/// Returns an error if the given `path` does not points to a `Cargo.toml`.
	pub fn with_project(self, path: impl Into<PathBuf>) -> Result<WasmBuilder, &'static str> {
		let path = path.into();

		if path.ends_with("Cargo.toml") && path.exists() {
			Ok(WasmBuilder {
				rust_flags: Vec::new(),
				file_name: None,
				project_cargo_toml: path,
				features_to_enable: Vec::new(),
			})
		} else {
			Err("Project path must point to the `Cargo.toml` of the project")
		}
	}
}

/// The builder for building a wasm binary.
///
/// The builder itself is separated into multiple structs to make the setup type safe.
/// 构建器本身被分成多个结构，以使设置类型安全。
/// Building a wasm binary:
/// 构建一个wasm二进制：
/// 1. Call [`WasmBuilder::new`] to create a new builder.
/// 1. 调用 [`WasmBuilder::new`] 去创建一个新的构建器。
/// 2. Select the project to build using the methods of [`WasmBuilderSelectProject`].
/// 2. 选择对应的项目并使用[`WasmBuilderSelectProject`]的方法去构建。
/// 3. Set additional `RUST_FLAGS` or a different name for the file containing the WASM code
///    using methods of [`WasmBuilder`].
/// 3. 使用[`WasmBuilder`]的方法为包含 WASM 代码的文件设置额外的 `RUST_FLAGS` 或其他名称。
/// 4. Build the WASM binary using [`Self::build`].
/// 4. 使用  [`Self::build`]构建wasm二进制。
pub struct WasmBuilder {
	/// Flags that should be appended to `RUST_FLAGS` env variable.
	/// 添加到`RUST_FLAGS`环境变量
	rust_flags: Vec<String>,
	/// The name of the file that is being generated in `OUT_DIR`.
	///	生成的文件名字
	/// Defaults to `wasm_binary.rs`.
	file_name: Option<String>,
	/// The path to the `Cargo.toml` of the project that should be built
	/// for wasm.
	/// 应该为 wasm 构建的项目的 `Cargo.toml` 的路径。
	project_cargo_toml: PathBuf,
	/// Features that should be enabled when building the wasm binary.
	/// 构建 wasm 二进制文件时应启用的功能。
	features_to_enable: Vec<String>,
}

impl WasmBuilder {
	/// Create a new instance of the builder.
	pub fn new() -> WasmBuilderSelectProject {
		WasmBuilderSelectProject { _ignore: () }
	}

	/// Enable exporting `__heap_base` as global variable in the WASM binary.
	///
	/// This adds `-Clink-arg=--export=__heap_base` to `RUST_FLAGS`.
	/// 启用将 `__heap_base` 导出为 WASM 二进制文件中的全局变量。
	/// 这会将 `-Clink-arg=--export=__heap_base` 添加到 `RUST_FLAGS`。
	pub fn export_heap_base(mut self) -> Self {
		self.rust_flags.push("-Clink-arg=--export=__heap_base".into());
		self
	}

	/// Set the name of the file that will be generated in `OUT_DIR`.
	///
	/// This file needs to be included to get access to the build WASM binary.
	///
	/// If this function is not called, `file_name` defaults to `wasm_binary.rs`
	/// 设置构建文件名称，需要包含此名称才能构建wasm 二进制。如果方法没被调用，则文件名默认为`wasm_binary.rs`
	pub fn set_file_name(mut self, file_name: impl Into<String>) -> Self {
		self.file_name = Some(file_name.into());
		self
	}

	/// Instruct the linker to import the memory into the WASM binary.
	/// 指示链接器将内存导入 WASM 二进制文件。
	/// This adds `-C link-arg=--import-memory` to `RUST_FLAGS`.
	pub fn import_memory(mut self) -> Self {
		self.rust_flags.push("-C link-arg=--import-memory".into());
		self
	}

	/// Append the given `flag` to `RUST_FLAGS`.
	///
	/// `flag` is appended as is, so it needs to be a valid flag.
	pub fn append_to_rust_flags(mut self, flag: impl Into<String>) -> Self {
		self.rust_flags.push(flag.into());
		self
	}

	/// Enable the given feature when building the wasm binary.
	///
	/// `feature` needs to be a valid feature that is defined in the project `Cargo.toml`.
	pub fn enable_feature(mut self, feature: impl Into<String>) -> Self {
		self.features_to_enable.push(feature.into());
		self
	}

	/// Build the WASM binary.
	/// 构建 wasm 二进制。
	pub fn build(self) {
		let out_dir = PathBuf::from(env::var("OUT_DIR").expect("`OUT_DIR` is set by cargo!"));
		let file_path =
			out_dir.join(self.file_name.clone().unwrap_or_else(|| "wasm_binary.rs".into()));//拼接wasm文件路径

		if check_skip_build() {
			// If we skip the build, we still want to make sure to be called when an env variable
			// changes
			// 如果我们跳过构建，我们仍然希望确保在环境变量更改时被调用
			generate_rerun_if_changed_instructions();

			provide_dummy_wasm_binary_if_not_exist(&file_path);

			return
		}

		build_project(
			file_path,
			self.project_cargo_toml,
			self.rust_flags.into_iter().map(|f| format!("{} ", f)).collect(),
			self.features_to_enable,
			self.file_name,
		);

		// As last step we need to generate our `rerun-if-changed` stuff. If a build fails, we don't
		// want to spam the output!
		// 作为最后一步，我们需要生成我们的 `rerun-if-changed` 东西。如果构建失败，我们不想向输出发送垃圾邮件！
		generate_rerun_if_changed_instructions();
	}
}

/// Generate the name of the skip build environment variable for the current crate.
/// 为当前 crate 生成跳过构建环境变量的名称。
fn generate_crate_skip_build_env_name() -> String {
	format!(
		"SKIP_{}_WASM_BUILD",
		env::var("CARGO_PKG_NAME")
			.expect("Package name is set")
			.to_uppercase()
			.replace('-', "_"),
	)
}

/// Checks if the build of the WASM binary should be skipped.
/// 检查是否应该跳过 WASM 二进制文件的构建。
fn check_skip_build() -> bool {
	env::var(crate::SKIP_BUILD_ENV).is_ok() ||
		env::var(generate_crate_skip_build_env_name()).is_ok()
}

/// Provide a dummy WASM binary if there doesn't exist one.
fn provide_dummy_wasm_binary_if_not_exist(file_path: &Path) {
	if !file_path.exists() {
		crate::write_file_if_changed(
			file_path,
			"pub const WASM_BINARY: Option<&[u8]> = None;\
			 pub const WASM_BINARY_BLOATY: Option<&[u8]> = None;",
		);
	}
}

/// Generate the `rerun-if-changed` instructions for cargo to make sure that the WASM binary is
/// rebuilt when needed.
/// 为 cargo 生成 `rerun-if-changed` 指令，以确保在需要时重建 WASM 二进制文件。
fn generate_rerun_if_changed_instructions() {
	// Make sure that the `build.rs` is called again if one of the following env variables changes.
	println!("cargo:rerun-if-env-changed={}", crate::SKIP_BUILD_ENV);
	println!("cargo:rerun-if-env-changed={}", crate::FORCE_WASM_BUILD_ENV);
	println!("cargo:rerun-if-env-changed={}", generate_crate_skip_build_env_name());
}

/// Build the currently built project as wasm binary.
/// 构建当前项目为wasm二进制。
/// The current project is determined by using the `CARGO_MANIFEST_DIR` environment variable.
/// 当前项目是通过使用 `CARGO_MANIFEST_DIR` 环境变量确定的。
/// `file_name` - The name + path of the file being generated. The file contains the
/// constant `WASM_BINARY`, which contains the built WASM binary.
/// `file_name` - 正在生成的文件的名称 + 路径。该文件包含常量“WASM_BINARY”，其中包含构建的 WASM 二进制文件。
/// `project_cargo_toml` - The path to the `Cargo.toml` of the project that should be built.
/// `project_cargo_toml` - 应该构建的项目的 `Cargo.toml` 的路径。
/// `default_rustflags` - Default `RUSTFLAGS` that will always be set for the build.
/// `default_rustflags` - 将始终为构建设置的默认 `RUSTFLAGS`。
/// `features_to_enable` - Features that should be enabled for the project.
/// `features_to_enable` - 应该为项目启用的功能。
/// `wasm_binary_name` - The optional wasm binary name that is extended with
/// `wasm_binary_name` - 扩展的可选 wasm 二进制名称
/// `.compact.compressed.wasm`. If `None`, the project name will be used.
/// `.compact.compressed.wasm`。如果为“无”，将使用项目名称。
fn build_project(
	file_name: PathBuf,
	project_cargo_toml: PathBuf,
	default_rustflags: String,
	features_to_enable: Vec<String>,
	wasm_binary_name: Option<String>,
) {
	let cargo_cmd = match crate::prerequisites::check() {
		Ok(cmd) => cmd,
		Err(err_msg) => {
			eprintln!("{}", err_msg);
			process::exit(1);
		},
	};

	let (wasm_binary, bloaty) = crate::wasm_project::create_and_compile(
		&project_cargo_toml,
		&default_rustflags,
		cargo_cmd,
		features_to_enable,
		wasm_binary_name,
	);

	let (wasm_binary, wasm_binary_bloaty) = if let Some(wasm_binary) = wasm_binary {
		(wasm_binary.wasm_binary_path_escaped(), bloaty.wasm_binary_bloaty_path_escaped())
	} else {
		(bloaty.wasm_binary_bloaty_path_escaped(), bloaty.wasm_binary_bloaty_path_escaped())
	};

	crate::write_file_if_changed(
		file_name,
		format!(
			r#"
				pub const WASM_BINARY: Option<&[u8]> = Some(include_bytes!("{wasm_binary}"));
				pub const WASM_BINARY_BLOATY: Option<&[u8]> = Some(include_bytes!("{wasm_binary_bloaty}"));
			"#,
			wasm_binary = wasm_binary,
			wasm_binary_bloaty = wasm_binary_bloaty,
		),
	);
}
