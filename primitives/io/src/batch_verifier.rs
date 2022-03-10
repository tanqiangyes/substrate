// This file is part of Substrate.

// Copyright (C) 2020-2022 Parity Technologies (UK) Ltd.
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

//! Batch/parallel verification.
//! 批量/并行验证

use futures::{channel::oneshot, future::FutureExt};
use sp_core::{crypto::Pair, ecdsa, ed25519, sr25519, traits::SpawnNamed};
use std::sync::{
	atomic::{AtomicBool, Ordering as AtomicOrdering},
	Arc,
};

#[derive(Debug, Clone)]
struct Sr25519BatchItem {
	signature: sr25519::Signature,
	pub_key: sr25519::Public,
	message: Vec<u8>,
}

/// Batch verifier.
/// 批量验证
/// Used to parallel-verify signatures for runtime host. Provide task executor and
/// just push (`push_ed25519`, `push_sr25519`) as many signature as you need. At the end,
/// call `verify_and_clear to get a result. After that, batch verifier is ready for the
/// next batching job.
/// 用于并行验证运行时主机的签名。提供任务执行器并根据需要推送（`push_ed25519`、`push_sr25519`）签名。
/// 最后，调用 `verify_and_clear 得到结果。之后，批处理验证器已准备好进行下一个批处理作业。
pub struct BatchVerifier {
	scheduler: Box<dyn SpawnNamed>,
	sr25519_items: Vec<Sr25519BatchItem>,
	invalid: Arc<AtomicBool>,
	pending_tasks: Vec<oneshot::Receiver<()>>,
}

impl BatchVerifier {
	pub fn new(scheduler: Box<dyn SpawnNamed>) -> Self {
		BatchVerifier {
			scheduler,
			sr25519_items: Default::default(),
			invalid: Arc::new(false.into()),
			pending_tasks: vec![],
		}
	}

	/// Spawn a verification task.
	/// 产生一个验证任务
	/// Returns `false` if there was already an invalid verification or if
	/// the verification could not be spawned.
	/// 如果已经存在无效验证或验证无法生成，则返回 `false`。
	fn spawn_verification_task(
		&mut self,
		f: impl FnOnce() -> bool + Send + 'static,
		name: &'static str,
	) -> bool {
		// there is already invalid transaction encountered
		if self.invalid.load(AtomicOrdering::Relaxed) {
			return false
		}

		let invalid_clone = self.invalid.clone();
		let (sender, receiver) = oneshot::channel();
		self.pending_tasks.push(receiver);

		self.scheduler.spawn(
			name,
			None,
			async move {
				if !f() {
					invalid_clone.store(true, AtomicOrdering::Relaxed);
				}
				if sender.send(()).is_err() {
					// sanity
					log::warn!("Verification halted while result was pending");
					invalid_clone.store(true, AtomicOrdering::Relaxed);
				}
			}
			.boxed(),
		);

		true
	}

	/// Push ed25519 signature to verify.
	/// 推送 ed25519 签名进行验证。
	/// Returns false if some of the pushed signatures before already failed the check
	/// (in this case it won't verify anything else)
	pub fn push_ed25519(
		&mut self,
		signature: ed25519::Signature,
		pub_key: ed25519::Public,
		message: Vec<u8>,
	) -> bool {
		self.spawn_verification_task(
			move || ed25519::Pair::verify(&signature, &message, &pub_key),
			"substrate_ed25519_verify",
		)
	}

	/// Push sr25519 signature to verify.
	/// 推送 sr25519 签名进行验证。
	/// Returns false if some of the pushed signatures before already failed the check.
	/// (in this case it won't verify anything else)
	pub fn push_sr25519(
		&mut self,
		signature: sr25519::Signature,
		pub_key: sr25519::Public,
		message: Vec<u8>,
	) -> bool {
		if self.invalid.load(AtomicOrdering::Relaxed) {
			return false
		}
		self.sr25519_items.push(Sr25519BatchItem { signature, pub_key, message });

		if self.sr25519_items.len() >= 128 {
			let items = std::mem::take(&mut self.sr25519_items);
			self.spawn_verification_task(
				move || Self::verify_sr25519_batch(items),
				"substrate_sr25519_verify",
			)
		} else {
			true
		}
	}

	/// Push ecdsa signature to verify.
	/// 推送 ecdsa 签名进行验证。
	/// Returns false if some of the pushed signatures before already failed the check
	/// (in this case it won't verify anything else)
	pub fn push_ecdsa(
		&mut self,
		signature: ecdsa::Signature,
		pub_key: ecdsa::Public,
		message: Vec<u8>,
	) -> bool {
		self.spawn_verification_task(
			move || ecdsa::Pair::verify(&signature, &message, &pub_key),
			"substrate_ecdsa_verify",
		)
	}

	fn verify_sr25519_batch(items: Vec<Sr25519BatchItem>) -> bool {
		let messages = items.iter().map(|item| &item.message[..]).collect();
		let signatures = items.iter().map(|item| &item.signature).collect();
		let pub_keys = items.iter().map(|item| &item.pub_key).collect();

		sr25519::verify_batch(messages, signatures, pub_keys)
	}

	/// Verify all previously pushed signatures since last call and return
	/// aggregated result.
	/// 验证自上次调用以来所有先前推送的签名并返回聚合结果
	#[must_use]
	pub fn verify_and_clear(&mut self) -> bool {
		let pending = std::mem::take(&mut self.pending_tasks);
		let started = std::time::Instant::now();

		log::trace!(
			target: "runtime",
			"Batch-verification: {} pending tasks, {} sr25519 signatures",
			pending.len(),
			self.sr25519_items.len(),
		);

		if !Self::verify_sr25519_batch(std::mem::take(&mut self.sr25519_items)) {
			return false
		}

		if pending.len() > 0 {
			let (sender, receiver) = std::sync::mpsc::channel();
			self.scheduler.spawn(
				"substrate-batch-verify-join",
				None,
				async move {
					futures::future::join_all(pending).await;
					sender.send(()).expect(
						"Channel never panics if receiver is live. \
								Receiver is always live until received this data; qed. ",
					);
				}
				.boxed(),
			);

			if receiver.recv().is_err() {
				log::warn!(
					target: "runtime",
					"Haven't received async result from verification task. Returning false.",
				);

				return false
			}
		}

		log::trace!(
			target: "runtime",
			"Finalization of batch verification took {} ms",
			started.elapsed().as_millis(),
		);

		!self.invalid.swap(false, AtomicOrdering::Relaxed)
	}
}
