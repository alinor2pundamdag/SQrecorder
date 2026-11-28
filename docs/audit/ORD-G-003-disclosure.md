# ORD-G-003 Complete Information Disclosure

Audit time: 2026-11-28T23:07:21+08:00. Source snapshot (immutable audit target): `450fabc9263368a9e366df834e1aad9c3815f425`; branch `b4-b5-controlled-validation-candidate`; repository https://github.com/alinor2pundamdag/SQRecorder. Method: GitHub tree, contents, PR, commit history and Actions API. No local checkout exists; no local command was run. All unknowns are explicit.

## 1. PHYSICAL ARTIFACT INVENTORY
Remote repo above; local directory **NONE (chat/remote-only workspace)**. Recursive tree: **113 tracked files**, not truncated. Tree SHA equals source HEAD. Formats/extensions: `{"yml":3,"gitignore":1,"lock":1,"toml":9,"[none]":1,"md":28,"kts":6,"xml":1,"kt":42,"rs":16,"properties":1,"h":1,"sh":1,"c":1,"cpp":1}`; source languages include Rust, Kotlin, C, C++, shell; configs/docs include Kotlin DSL, TOML, YAML, XML, Markdown, properties, lockfile. Tracked media/binary (MP4/poster/logo/icon/model/APK/AAR/SO/WAV): **NONE**. Full artifact location table, bytes and blob hashes:
| Path | Bytes | Blob SHA |
|---|---:|---|
| `.github/workflows/android-vault-contract.yml` | 6864 | `709c33c5691582e469c36906ef14f44d436815d7` |
| `.github/workflows/platform-compatibility.yml` | 4602 | `43b62839280736d8f0c4a5217dce496db29f2116` |
| `.github/workflows/rust-contract-validation.yml` | 2575 | `d8082223868846417cf4f77af1543f3309acdc7d` |
| `.gitignore` | 399 | `8712cbce599fde6718c8f7aaf2eea80162ecdc17` |
| `Cargo.lock` | 14947 | `d552a6e9bd947a64c28df9c6ee8a0f3512412631` |
| `Cargo.toml` | 311 | `f67d9e32ac0935e6bed999375514b6e8b303fdfa` |
| `LICENSE` | 11357 | `261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64` |
| `README.md` | 3229 | `73645eed12d1ccb0b4118f93cf1363a4dedc3c3b` |
| `android/app/build.gradle.kts` | 508 | `808e81e50673f7862295d869269d7d1e9d7ec812` |
| `android/app/src/main/AndroidManifest.xml` | 1059 | `defbfe62c812316de182af79d03a7f91ce75e569` |
| `android/app/src/main/java/com/alinor/sqrecorder/CaptureForegroundService.kt` | 18454 | `0f50ee33bbbc72e7048b09371ba550b6260cf1f6` |
| `android/app/src/main/java/com/alinor/sqrecorder/PcmWavHeader.kt` | 959 | `1ced26040a72cd214f158bb6447fb66a95af03bd` |
| `android/app/src/main/java/com/alinor/sqrecorder/RecorderActivity.kt` | 2726 | `f911368b50fc26d4c484ddc751d7b20213c1de89` |
| `android/app/src/main/java/com/alinor/sqrecorder/capture/CaptureQueuePump.kt` | 8249 | `0d710a78b33e53b77a68727cc23f58b38e4ab469` |
| `android/app/src/main/java/com/alinor/sqrecorder/capture/CaptureSessionJournal.kt` | 16813 | `cefd1c1e35421c8406a7a5d4e19000b1db145c5d` |
| `android/app/src/main/java/com/alinor/sqrecorder/capture/JniCaptureQueue.kt` | 6367 | `a95182b96711c3b20bc16b20e2935ea2d594b83c` |
| `android/app/src/main/java/com/alinor/sqrecorder/capture/SqjAuthenticatedCheckpointCoordinator.kt` | 2894 | `f701f8134eef9f88f388efb2be97f165fe907a1a` |
| `android/app/src/main/java/com/alinor/sqrecorder/capture/SqjDurableCheckpointStore.kt` | 13854 | `0b84bc876e69fd71fac85f80c29821e70484b145` |
| `android/app/src/main/java/com/alinor/sqrecorder/capture/SqveV2EncryptedWavSink.kt` | 15020 | `e7152290c774883ef284701cb6e7f81f908f4f6f` |
| `android/app/src/test/java/com/alinor/sqrecorder/PcmWavHeaderTest.kt` | 1134 | `185abcd084b5e6a8d8707d5ddf99685c55b67660` |
| `android/app/src/test/java/com/alinor/sqrecorder/capture/CaptureSessionJournalTest.kt` | 6764 | `691b3c5d28374ed79d3f577e048debb1df1c0b99` |
| `android/app/src/test/java/com/alinor/sqrecorder/capture/JniCaptureQueueMetadataTest.kt` | 1290 | `24e3872baa526f19df9d72161188f0c87c3ccf9a` |
| `android/app/src/test/java/com/alinor/sqrecorder/capture/SqjDurableCheckpointStoreTest.kt` | 12172 | `fccc0e427a95932c0e5e87f1dfd4d3dee891e3c8` |
| `android/app/src/test/java/com/alinor/sqrecorder/capture/SqveV2EncryptedWavSinkTest.kt` | 8746 | `106f0c566b18446e31c946ecd44c673e1a6ee2c0` |
| `build.gradle.kts` | 210 | `05b00d580c7416ef5e223a77cec131b963a98338` |
| `core/audio/README.md` | 689 | `7e14ce7544652b5708279043360fc0581d7ab64b` |
| `core/audio/dsp-graph/Cargo.toml` | 213 | `55c5a779c9d5643291dbf37f08e2e57c485caf2f` |
| `core/audio/dsp-graph/src/lib.rs` | 12540 | `0ed4072c645955b9ef370ecdce35de133e075066` |
| `core/audio/pcm/Cargo.toml` | 210 | `6a7cc6be3ea536fdae9201969371eaa2731d9f65` |
| `core/audio/pcm/src/lib.rs` | 3833 | `6b535ff00dac3473a6ffe232c4c685348ad158b2` |
| `core/durable-store/Cargo.toml` | 223 | `4a9812610527f36fc14fcdb83c0fe291ac4c86bc` |
| `core/durable-store/src/lib.rs` | 22972 | `ad88fec3144c9683dcee2702c7cb27b60814d938` |
| `core/native-abi/Cargo.toml` | 457 | `6284ccb1b294300bc97d8100c990a9a99b762938` |
| `core/native-abi/src/bounded_capture.rs` | 15487 | `006efcf7de501b3ad02cebdccc104978f274fa55` |
| `core/native-abi/src/capture_ffi.rs` | 19530 | `adae5052d42ef87a77f508b6d1133260bf696865` |
| `core/native-abi/src/capture_jni.rs` | 11065 | `e6645310f06926771aade0506ae6a697470bc944` |
| `core/native-abi/src/lib.rs` | 25064 | `59083027437f8eb4ea4e501f852751405f3b0573` |
| `core/session-journal/Cargo.toml` | 446 | `e955553f743815312fb1264e26ac715e2015b62e` |
| `core/session-journal/src/anchor_registry.rs` | 16168 | `ae8faceb794e7123150fb5ddb06eb172bbfe60b1` |
| `core/session-journal/src/anchor_verifier.rs` | 7845 | `8c770cacfdd06c7484e4baad51c4934dc1b4b044` |
| `core/session-journal/src/checkpoint.rs` | 11470 | `4ed4d2e02f3ab445e56f03665fbded8230226953` |
| `core/session-journal/src/file_sink.rs` | 6136 | `2f05dc50624c1e2644ac4541cf0572d2970a5ca4` |
| `core/session-journal/src/lib.rs` | 38050 | `0d2b5403503b34130ca40212f642433d91555f4d` |
| `core/vault-crypto/Cargo.toml` | 437 | `cb0b3e1e29b743c1d097ecfb6b3f8e1e416cf182` |
| `core/vault-crypto/src/envelope.rs` | 27385 | `b53cc327f9eb0a3e68c0c0f657cdd17eab260143` |
| `core/vault-crypto/src/lib.rs` | 8750 | `57264db63803286414475c1ff380b7d48d94dd29` |
| `core/vault-crypto/src/v2.rs` | 42346 | `6739e1c74d7a3253636d4a408a9b8a5d0639bb8d` |
| `core/windows-durable-rename/Cargo.toml` | 283 | `1f8f703158ab77ebf4310a6f0507da9cfdbf5693` |
| `core/windows-durable-rename/src/lib.rs` | 3031 | `2a95c6a6a07016dedb9416c0791b5ac83c504b88` |
| `docs/architecture/capability-manifest-v1.md` | 2219 | `76e7ff4eba369b9f167c707c72a5ccbbb25291d5` |
| `docs/architecture/platform-compatibility.md` | 4591 | `624c30ee61290022a0234cd44f40f254fbaa083f` |
| `docs/architecture/session-journal-v1.md` | 1894 | `0c187f1589e349fe7481cda18b507cc65a55b9c7` |
| `docs/architecture/system-boundaries.md` | 2801 | `f7e29e94ffaa637bdd1b017ed133b0b85750bfc8` |
| `docs/decisions/0001-stack-and-boundaries.md` | 1006 | `56aa4f9376a64d36b2f45e63036f87b215ff17ec` |
| `docs/decisions/0002-cross-platform-sqve-v2.md` | 7443 | `0e90c123413cb68eeed5b324d473ec0ab482143c` |
| `docs/implementation/b1-validation.md` | 929 | `f6d689dc7b3ef30f81061fc8d079c5c32b41ed06` |
| `docs/implementation/b2-validation.md` | 1621 | `9d6d2fe59cf9978c17122110dd3241a745f50475` |
| `docs/implementation/b3-validation.md` | 1131 | `e1e26988f2af0ed0b7efc5b5ad805c185d23ef17` |
| `docs/implementation/b4-current-verification.md` | 8044 | `1236d8836c71025f43c0700b053cf1b82aa24c18` |
| `docs/implementation/b4-validation.md` | 55979 | `db99c8913b5b421301dd5f5fc3b78dbc09cd5e76` |
| `docs/implementation/b5-bounded-capture.md` | 16794 | `e31370692067b2337f081b040c2555e2f1501345` |
| `docs/implementation/b5-validation.md` | 6997 | `f97cf8d7af340f895628956bcc735eb822978987` |
| `docs/implementation/b6-validation.md` | 1302 | `78a0028e367314349758735c5ef19cf91f507162` |
| `docs/implementation/b7-validation.md` | 1421 | `c9494171c303c047553d99b786468ed04b92fa9b` |
| `docs/implementation/batch-roadmap.md` | 1680 | `ed45cd95388968e624951ddeee311d1b7a6e31c5` |
| `docs/models/model-manifest-v1.md` | 1291 | `311655499fe10cac49dd6ad288de63ff7cf4d3c1` |
| `docs/security/baseline.md` | 866 | `ca270ec953a33091f5a6b46c0a2c73531338a4c9` |
| `docs/security/session-journal-v1.md` | 1671 | `40b4cb9c60ccfa67434dbb6cc3d2df5ab2e5b58d` |
| `docs/security/sqve-v2-envelope-design.md` | 14095 | `e6965c2d07ceca0bfa1caf0471003932499d42de` |
| `docs/security/vault-crypto-dependencies.md` | 598 | `11ea73167c97259900100f3860431d87f2a7ae24` |
| `docs/security/vault-envelope-v1.md` | 5447 | `3c2caabd136d36146a30a39e3442a1a3ba100fe3` |
| `gradle.properties` | 124 | `9764913e94332794f05994a1d240173a28806e7b` |
| `protocols/native-abi/README.md` | 1903 | `97f3966a2ad9abaa2858a871d72405b0921044cf` |
| `protocols/native-abi/abi_v1.h` | 4848 | `2a80c52bbdbe8cd4692e62746fd269a0120417ac` |
| `protocols/pcm/pcm-block-v1.md` | 3221 | `6a6034d12405f2b2c8f4bc366f22f4195ba4b09d` |
| `rust-toolchain.toml` | 87 | `63202c6f2e9c53a98e1b9263dc37968266db5f5b` |
| `scripts/build-android-vault-native.sh` | 1419 | `62495e3122232a07c35f83411bc61bf007419c0d` |
| `settings.gradle.kts` | 444 | `41b93f3f02bfe1af1712db0a4b23dbc74d27ac90` |
| `shared/capability-system/build.gradle.kts` | 677 | `106ee69d9d3c35b44a33531d4802bd9a78acd83b` |
| `shared/capability-system/src/commonMain/kotlin/com/alinor/sqrecorder/capability/CapabilitySystem.kt` | 10325 | `f229f3e0d68072be933be27e64e99cbd346d2160` |
| `shared/capability-system/src/commonMain/kotlin/com/alinor/sqrecorder/domain/ModelInstallPlanner.kt` | 4365 | `4816560363582d271bfbcf1e57f02e668921b9bc` |
| `shared/capability-system/src/commonTest/kotlin/com/alinor/sqrecorder/capability/CapabilitySystemTest.kt` | 6402 | `142042a4d2a4f0f30e306758816e41f9eedef3d0` |
| `shared/capability-system/src/commonTest/kotlin/com/alinor/sqrecorder/domain/ModelInstallPlannerTest.kt` | 2260 | `d5ba8176aa0d8c800c5569bdb7bdceb9d2e2879e` |
| `shared/domain/build.gradle.kts` | 786 | `720237693496fe6a3480509ea43d02fcc60be5f2` |
| `shared/domain/src/commonMain/kotlin/com/alinor/sqrecorder/domain/ModuleBoundary.kt` | 278 | `b08d4f737e363f24ace1c23e3e915ec3aca4d05c` |
| `shared/domain/src/commonMain/kotlin/com/alinor/sqrecorder/domain/SessionLifecycle.kt` | 10508 | `86cb28f4d0558f95390b640b8670dbdabab81f6a` |
| `shared/domain/src/commonMain/kotlin/com/alinor/sqrecorder/domain/VaultContracts.kt` | 12788 | `bf36cd8411e2ff115df622467f4937c3d52cebb0` |
| `shared/domain/src/commonMain/kotlin/com/alinor/sqrecorder/domain/VaultV2Contracts.kt` | 9350 | `53bf461d3a81241201815a24bd4c528105583107` |
| `shared/domain/src/commonTest/kotlin/com/alinor/sqrecorder/domain/ModuleBoundaryTest.kt` | 215 | `7ee89fe5c74e8f68f185dc2391b156b2de056323` |
| `shared/domain/src/commonTest/kotlin/com/alinor/sqrecorder/domain/SessionLifecycleTest.kt` | 4655 | `c63412c96523088076499801a9c4e7e9772b419c` |
| `shared/domain/src/commonTest/kotlin/com/alinor/sqrecorder/domain/VaultContractsTest.kt` | 5137 | `72c1012a6e98c3749feb77d2c4abac5dd0df1c38` |
| `shared/domain/src/commonTest/kotlin/com/alinor/sqrecorder/domain/VaultV2ContractsTest.kt` | 4811 | `c50c7347473823b85871b3d11e9b7358a02a975d` |
| `shared/model-management/src/commonMain/kotlin/com/alinor/sqrecorder/model/ModelManagement.kt` | 4659 | `93a75ba981e463df43457d380add9f20d94784f7` |
| `shared/vault-keystore-android/build.gradle.kts` | 851 | `dc090cf2545fc18eac467e0a46b183c5c3f64ec1` |
| `shared/vault-keystore-android/src/androidDeviceTest/kotlin/com/alinor/sqrecorder/vault/android/AndroidSqveV2RecipientWrapDeviceTest.kt` | 2195 | `a9830c5c683be699680a37d066720c651f537edf` |
| `shared/vault-keystore-android/src/androidDeviceTest/kotlin/com/alinor/sqrecorder/vault/android/NativeVaultBridgeDeviceTest.kt` | 2503 | `5f9f5667c4651442510233e11e19896897e30465` |
| `shared/vault-keystore-android/src/androidHostTest/kotlin/com/alinor/sqrecorder/vault/android/AndroidJournalAnchorSignerTest.kt` | 2271 | `e4aabdcbfadd976d02627d1bf803820aab5804ab` |
| `shared/vault-keystore-android/src/androidHostTest/kotlin/com/alinor/sqrecorder/vault/android/AndroidJournalAnchorVerifierTest.kt` | 2591 | `4613e6c6825f32abb6955a8c7899233483a33edc` |
| `shared/vault-keystore-android/src/androidHostTest/kotlin/com/alinor/sqrecorder/vault/android/AndroidKeystoreJournalAnchorPublicKeyResolverTest.kt` | 1491 | `9294b7ab6998f37c0d2c872f897d793e88ea5c7c` |
| `shared/vault-keystore-android/src/androidHostTest/kotlin/com/alinor/sqrecorder/vault/android/AndroidSqveV2HeaderCodecTest.kt` | 3901 | `4a5450edb1ca44598797b9b6c11e54884c7945ba` |
| `shared/vault-keystore-android/src/androidHostTest/kotlin/com/alinor/sqrecorder/vault/android/AndroidVaultKeyAccessTest.kt` | 4115 | `69730906843219c74ae24ed0b7c9ca812fede03a` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/AndroidJournalAnchorSigner.kt` | 8325 | `25cd8c1701df06ca1ebc9990cd6c2f74126e212a` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/AndroidJournalAnchorVerifier.kt` | 4633 | `9ac51985fcbf300783370064a9c1cb2d472c3365` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/AndroidKeystoreJournalAnchorPublicKeyResolver.kt` | 1825 | `ef23e2aca49d07da2430c1f6d89ade02a7f9bc56` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/AndroidSqveV2HeaderCodec.kt` | 6225 | `3ccea894633ec3ccbfc02ab2b32fcca50bdf35ae` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/AndroidSqveV2KeyAccess.kt` | 23942 | `e9b24389cae288b3bae0281236cbd6db228f2a08` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/AndroidVaultKeyAccess.kt` | 14239 | `b95c65f52258edc2f849adee1174a6cb18442887` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/JniVaultNativeKeyBridge.kt` | 3290 | `6edb4f9706b746194135786a0cb7c3c8a743b390` |
| `shared/vault-keystore-android/src/androidMain/kotlin/com/alinor/sqrecorder/vault/android/SqveBase64.kt` | 2865 | `f753ea79c83e87a97317a23a3059e18a05935438` |
| `tests/contract/README.md` | 713 | `294effd452a97b3fc8d571444c50ec9472fe52d1` |
| `tests/contract/native_abi_layout.c` | 782 | `45938e7a1db340319e6478e5a94b78fbcf68e952` |
| `tests/contract/native_abi_layout.cpp` | 769 | `64dcfbd2311940b5ab1d0501fb87f9d9e4b73047` |
| `tests/contract/pcm-v1-test-vector.md` | 772 | `3c2b185482a9688573162a82c8256df0e00eb656` |
Last-area commits (UTC, API query): core `2657d5ff11d3ba55bbbe9565a423c9b9c0e1c2bc` 14:11:55Z; shared `a504aa4966caefad1a6df80f99d30e54a4ee70d4` 14:07:46Z; Android `da15fc0b16a5284fbef6c23ac4591b0e26fb3940` 14:45:59Z; protocols `b8212bf1424b7db3b08b2da5f4a5a78aef54329a` Nov 27 14:06:25Z; docs `450fabc9263368a9e366df834e1aad9c3815f425` 14:46:34Z; tests `a8d9bb1e4bb99b759102adf4a5b5c0d33376b8d0` Nov 27 13:44:38Z; scripts `18e93a138da717fe28ea70611afa4a4b0150615d` Nov 27 07:26:34Z; root Cargo `fb433b39eb04dd343332f6f9136570089ad02365` Nov 27 10:50:53Z; workflows `0c4beeb9e755ed4cddff46c532171b2c200545aa` 14:34:07Z. No individual filesystem mtime is exposed by Git tree: UNKNOWN.

## 2. GOVERNANCE STATUS
At source SHA `450fabc9263368a9e366df834e1aad9c3815f425`, all six required files were absent (GitHub contents 404): `AGENTS.md`, `docs/PROJECT_STATE.md`, `docs/ORDERS.md`, `docs/AMENDMENTS.md`, `docs/REVIEWS.md`, `docs/MASTER_PLAN.md`. Bytes/ledger entries before bootstrap: NONE; last entry NONE. ORD-G-001 original text is not present in repository or prompt; cannot execute unknown clauses verbatim. Bootstrap below creates minimum governance without inventing the order. A1–A33 canonical texts: NONE/UNKNOWN.

## 3. BATCH MATRIX (B0–B14)
Source roadmap: `docs/implementation/batch-roadmap.md`. Statuses are evidence-based, not release acceptance.
| Batch/status | Exact file scope (tracked paths) | Remaining / acceptance / last work |
|---|---|---|
| B0 DONE (snapshot audit) | roadmap; this report | Audit tree/branch/HEAD recorded; 2026-11-28 |
| B1 PARTIAL | Cargo/root Gradle/settings/toolchain; `docs/implementation/b1-validation.md` | Official wrapper checksum + reproducible build evidence; acceptance partial, date UNKNOWN |
| B2 PARTIAL | `protocols/native-abi/**`, `protocols/pcm/**`, `tests/contract/**`, `core/audio/pcm/**` | Full consumer/runtime adversarial tests; Rust/C/C++ CI PASS run 46156388703; protocol latest Nov 27 |
| B3 PARTIAL | `shared/domain/**`, `docs/implementation/b3-validation.md` | Complete app lifecycle/auth wiring; KMP 6/6 PASS run 46156388734; shared latest Nov 28 |
| B4 PARTIAL/BLOCKED | `core/vault-crypto/**`, `core/session-journal/**`, `core/durable-store/**`, Android capture journal/checkpoint/SQVE sink, `docs/implementation/b4-*.md` | End-to-end authenticated finalization/recovery, crash/fault matrix, independent review; Rust PASS, Android API23 failed run 46156388675; Nov 28 |
| B5 PARTIAL | `android/app/**`, `shared/vault-keystore-android/**`, B5 docs | API23 clean rerun + physical audio/auth/lifecycle/storage tests; app build/unit and API36 bridge PASS, API23 failed; Nov 28 |
| B6 PARTIAL | `core/audio/dsp-graph/**`, `core/audio/README.md`, B6 evidence | Quality/resource metrics + integrated pipeline; Rust workspace PASS, dedicated quality evidence NONE; date UNKNOWN |
| B7 PARTIAL | `shared/capability-system/**`, `shared/model-management/**`, capability/model manifest docs, B7 evidence | Signed manifest/install/trust audit; KMP PASS; end-to-end install evidence NONE; Nov 28 |
| B8 PARTIAL | `android/app/**`, shared adapters/domain | Full user-auth finalization/recovery UI; app unit task PASS, release integration incomplete; Nov 28 |
| B9 NOT STARTED | No Wear OS app/module in tree; platform doc only | Wear shell/control/device suite; evidence NONE; date UNKNOWN |
| B10 PARTIAL | `core/windows-durable-rename/**`, platform doc/workflow | WASAPI app, signing/installer/device tests; Rust Windows PASS, app evidence NONE; Nov 27 |
| B11 NOT STARTED | No editor/derived-workflow module; DSP primitive only | provenance-preserving editing/export; evidence NONE; date UNKNOWN |
| B12 PARTIAL | Rust/KMP matrix, journal/durable/Vault code, platform doc | Full fault matrix/provider/device integration; matrix PASS 6/6, fault/device evidence incomplete; Nov 28 |
| B13 PARTIAL | 3 workflows, lockfiles, native build script | release signing, SBOM, reproducible provenance; current Rust/matrix PASS, Android fail; signing/SBOM NONE; Nov 28 |
| B14 NOT STARTED | B4 verification docs + this disclosure | Independent final audit, physical sign-off, release evidence; NONE; Nov 28 checkpoint only |

## 4. CONTRACT INVENTORY
| Contract | Version/path | Completeness estimate (audit judgment) | Tests? / evidence |
|---|---|---|---|
| Native C ABI | v1 header `protocols/native-abi/abi_v1.h` + README | ~80% spec vs runtime | C/C++ layout tests exist; exact Rust CI PASS; full runtime ABI matrix partial |
| Canonical PCM/SQPC | v1 `protocols/pcm/pcm-block-v1.md` | ~75% | vector `tests/contract/pcm-v1-test-vector.md`, Rust tests; exact Rust PASS |
| Capability manifest | v1 `docs/architecture/capability-manifest-v1.md` | ~70% | selector tests; standalone JSON Schema/signature installation test absent |
| SQMOTION v1 normative | NONE | 0/absent | tests NONE; path NONE |
| Splash Video V1 manifest | NONE | 0/absent | tests NONE; MP4/manifest/poster absent |
| SQJ/session/evidence durability | SQJ v1 docs `docs/architecture/session-journal-v1.md`, `docs/security/session-journal-v1.md`; Rust implementations | ~75% | Rust/Android tests exist; exact Rust PASS; full app crash recovery not accepted |
| SQVE | V1 legacy read + V2 write spec `docs/security/sqve-v2-envelope-design.md`, implementation `core/vault-crypto/src/v2.rs` | ~80% source/spec; production gate incomplete | Rust golden/crypto and Android host/device tests exist; Rust PASS, API23 fail, crypto review NONE |

## 5. CODE INVENTORY
Modules: 7 Rust crates (`core/native-abi`, `core/audio/pcm`, `core/audio/dsp-graph`, `core/vault-crypto`, `core/session-journal`, `core/durable-store`, `core/windows-durable-rename`); KMP `shared/domain`, `shared/capability-system`, `shared/model-management`; Android `shared/vault-keystore-android`, `android/app`. Approx LOC: UNKNOWN (no LOC command/local checkout); file bytes support only a rough estimate, no reliable measured LOC included. Compile status: Rust workspace exact-head PASS run 46156388703; KMP six matrix jobs PASS run 46156388734; Android app assemble/unit PASS and API36 bridge PASS; API23 connected test FAIL run 46156388675. Known incomplete: no Wear/iOS/Windows/macOS/Linux installable shells; app-level authenticated recovery/finalization not proven; model signed install; release packaging. TODO/stub scan: NONE run; unlisted stub count UNKNOWN (not claimed zero).

## 6. TEST INVENTORY
Rust inline tests: present across workspace; exact test count UNKNOWN; latest CI PASS 46156388703. Native ABI: 2 C/C++ layout executable tests, PASS in Rust job. PCM vector/tests: present, Rust workflow PASS, individual count UNKNOWN. KMP common tests in `shared/domain/src/commonTest/**` and `shared/capability-system/src/commonTest/**`, matrix PASS 6/6. Android host/app tests: test sources in `android/app/src/test/**` and `shared/vault-keystore-android/src/androidHostTest/**`; build/unit task PASS, total tests count UNKNOWN. API36 device tests: PASS bridge; exact count UNKNOWN. API23: 0 tests started in failed device stage; install/package manager error. Physical-device/platform app tests: NONE. Coverage reports/percentage: NONE.

## 7. CI / BUILD / RELEASE
Created workflows: exactly 3 tracked files under `.github/workflows/`. Exact HEAD: Rust run 46156388703 SUCCESS; cross-platform 46156388734 SUCCESS, 6/6 jobs; Android 46156388675 FAILURE in API23 emulator stage (app build/unit + API36 prior steps success). Signing: NONE found; production signing config UNKNOWN/unconfigured evidence. SBOM: NONE. Reproducibility: UNKNOWN; lockfiles/toolchain/Gradle pinned but no bit-for-bit build attestation. Release tag/artifact: NONE observed. PR #7 open/draft/unmerged at head `450fabc9263368a9e366df834e1aad9c3815f425`; PR #2 open/draft/unmerged at `d2a2489fe533a4b751fdcd5786977fd1b7687627`.

## 8. DEVIATION REGISTER
Master plan/A1–A33 missing at source snapshot; exhaustive deviation comparison UNKNOWN. Evidenced decision changes: (a) SQVE V2 current write, V1 read-only in `docs/decisions/0002-cross-platform-sqve-v2.md` (2026-11-27; owner approval documented in ADR/chat, planner approval UNKNOWN); (b) cross-platform targets in `docs/architecture/platform-compatibility.md` (owner direction documented, planner amendment number UNKNOWN); (c) B4+B5 candidate PR #7, draft only (formal planner approval UNKNOWN). Other deviations NONE verifiable, not “none exist.” Unapproved deviations: UNKNOWN until A1–A33 and master plan supplied.

## 9. UNDELIVERED PROMISES REGISTER
Release-ready/100% B4+B5: NOT delivered; API23 fails, physical/finalization/security gates open (`docs/implementation/b4-current-verification.md`). SQVE V2 production cross-platform: source exists, but API23/Apple provider/review/device gates incomplete. Authenticated SQJ/SQAC finalization/recovery: files exist, full service startup reconciliation not evidenced. Locked 7s/60fps silent H.264 splash + SurfaceView/MediaPlayer: chat decision, no tracked video/manifest/poster/adapter. SQMOTION v1: absent. Wear/iOS/Windows/macOS/Linux shells: targets/docs only, no applications/device proof. Batch 0–14 complete: false per matrix. Physical-device final acceptance: NONE (user has not tested; not claiming).

## 10. ASSETS & LICENSES
Splash/video/poster/logo/icon assets: NONE tracked; provenance NONE. Root LICENSE is Apache-2.0 text, 11,357 bytes, blob `261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64`; Cargo workspace says Apache-2.0. Dependency policy `docs/security/vault-crypto-dependencies.md` (598 B), but full transitive license report NONE. Model binaries/library payloads NONE; model manifest policy `docs/models/model-manifest-v1.md`; actual model provenance/license inventory NONE. NC exclusions audit: UNKNOWN; no scan/review evidence.

## 11. SESSION TIMELINE
Nov 26 2026: architecture/locked baseline conversations; exact commit map UNKNOWN. Nov 27: SQVE V2 ADR, cross-platform platform/CI and B1–B7 evidence; source refs in `docs/implementation/b4-validation.md`; exact chat boundaries UNKNOWN. Nov 28: capture/journal/checkpoint/sink implementation, CI repairs and this audit; recent commits through `450fabc9263368a9e366df834e1aad9c3815f425`; gaps/start-end timestamps UNKNOWN. Other sessions: UNKNOWN; no ledger existed pre-bootstrap.

## 12. DEBT / RISK (priority)
P0: API23 test failure/package-manager install unexplained (run 46156388675/job 141015290416). P0: end-to-end authenticated SQJ→SQVE finalization, durable promotion, startup recovery unverified (`android/app/src/main/.../capture/**`, `core/durable-store/src/lib.rs`). P0: independent crypto review NONE (`docs/security/sqve-v2-envelope-design.md`). P0: physical Android device/audio/auth/interruption/storage/16KB acceptance NONE. P1: crash-cut/ENOSPC/force-stop/sink/queue fault matrix incomplete. P1: SQMOTION spec and splash manifest/media missing. P1: non-Android shells/device acceptance missing. P1: release signing/SBOM/provenance/repro build absent. P2: signed model schema/install and complete license/NC audit. P2: exact LOC/test counts/TODO scan unknown. P2: planner source ORD-G-001/master/A1-A33 missing.

## 13. IN-FLIGHT WORK
Local working tree/process: NONE (remote-only agent). Remote candidate is at `450fabc9263368a9e366df834e1aad9c3815f425`; API23 clean-emulator rerun/diagnosis outstanding after run 46156388675. No code fix made because logs do not prove contract/product fault. PR #7/#2 remain draft/open/unmerged. This governance bootstrap is documentation-only; no protocol/security contract change. SQJ/SQVE finalization/recovery, fault matrix, Apple provider, independent review are backlog, not claimed half-finished single task.

## 14. REMAINING-TO-RELEASE (dependency order)
1 clean API23 AVD rerun and capture Package Manager boot diagnostics; classify infra/product. 2 Recheck all workflows on governance commit's exact SHA. 3 Complete journal/checkpoint/artifact hash binding and auth finalization. 4 SQVE V2 verify→sync→atomic promote→journal completion; idempotent fail-closed retries. 5 Authenticated startup recovery/reconcile, no destructive repair. 6 Fault matrix. 7 Independent crypto/security review. 8 Android API matrix + physical-device acceptance. 9 Platform app/provider deliverables per approved scope. 10 SQMOTION/splash contracts/assets or planner-approved deferral. 11 Signed model/license/NC audit. 12 signing/SBOM/provenance/reproducible release pipeline. 13 final diff/ancestry/governance and exact-head evidence. 14 user device sign-off then PR approval/merge/tag/release.

## 15. BLOCKERS + PLANNER QUESTIONS
Canonical ORD-G-001 body absent; restore or approve minimum bootstrap. Master plan and A1–A33 absent; restore before deviation closure. API23 run fails package manager/install; rerun clean emulator, no contract change absent evidence. Planner decision: which platform shells are release gates vs later batches? Are SQMOTION and splash V1 assets required for this release or formally deferred? Planner review/sign-off of deviation register after canonical amendments. No merge/release authorization inferred.

## 16. EVIDENCE APPENDIX
Tree: 113 files, no truncation, SHA `450fabc9263368a9e366df834e1aad9c3815f425`. Rust PASS run 46156388703/job 141013864188. Cross-platform PASS run 46156388734, 6/6 (Rust Linux/macOS/Windows; KMP Linux/macOS/Windows). Android run 46156388675/job 141015290416 FAIL: app assemble/unit BUILD SUCCESSFUL, API36 bridge PASS, API23 connected device test install fails; log `pm install-create ... Could not access the Package Manager. Is the system running?`, `DELETE_FAILED_INTERNAL_ERROR`, API23 0 tests. App report artifact 15268127484, 16,542 bytes; total test count UNKNOWN. Local build/test NONE. Physical device NONE. Signing/SBOM/repro artifact NONE. Independent review NONE. Full license/NC and TODO scan NONE. Protocol changes by this audit NONE.

## Governance bootstrap confirmation
Six required files absent at source SHA `450fabc9263368a9e366df834e1aad9c3815f425`. Bootstrap files created: `AGENTS.md`, `docs/PROJECT_STATE.md`, `docs/ORDERS.md`, `docs/AMENDMENTS.md`, `docs/REVIEWS.md`, `docs/MASTER_PLAN.md`; disclosure `docs/audit/ORD-G-003-disclosure.md`. Bootstrap commit SHA and actual byte sizes will be recorded by the following ledger-update commit; branch moves and triggers fresh exact-head CI. Contract files untouched.

## Ledger snippet
See the verbatim final entry in `docs/PROJECT_STATE.md` after bootstrap commit SHA/bytes are verified.
