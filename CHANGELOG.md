## [v1.1.5] – 2025-12-09
### Added
- (Describe changes here)

## [v1.1.5] – 2025-12-06
### Added
- (Describe changes here)

## [v1.1.4] – 2025-12-06
### Added
- (Describe changes here)

## [v1.1.3] – 2025-12-05
### Added
- (Describe changes here)

## [v1.1.2] – 2025-12-05
### Added
- (Describe changes here)

## [v1.1.1] – 2025-12-05
### Added
- (Describe changes here)

# CHANGELOG

All notable changes to **zeroizepy** will be documented in this file.

The format is based on **Keep a Changelog**, and this project adheres to **Semantic Versioning**.

---

## **[1.0.0] – 2025-12-04**
### Added
- Initial stable release of **zeroizepy**.
- **SecureMemory**: locked, zeroizable memory regions with optional libsodium backend.
- **secret_bytes()** helper for secure byte storage.
- **CryptoKey** with AES-GCM authenticated encryption and decryption.
- **Cryptographic erasure** (destroy key → data permanently unrecoverable).
- **File wiping**: multi-pass secure deletion with random or fixed patterns.
- **wipe_free_space()** for overwriting unallocated disk blocks.
- **SecureSession**: automatic lifecycle management of temp files and secrets.
- **OS-level erase wrappers** (hdparm, NVMe format, diskutil, BitLocker) – gated behind advanced use.
- Cross-platform implementation across Linux, macOS, and Windows.
- Comprehensive test suite with platform-specific skip logic.
- Full documentation of limitations and cross-platform caveats.

### Changed
- N/A – first stable release.

### Fixed
- N/A – first stable release.

---

## **[Unreleased]**
### Planned
- Secure in-process key derivation primitives.
- Hardware-accelerated backend for AES-GCM.
- Optional Rust extension module for high-security memory control.
- Windows VirtualLock fallback improvements.
- More deterministic sparse-file detection across OSes.
- Overwrite-strategy plugins (Gutmann, Schneier, DoD variants).
