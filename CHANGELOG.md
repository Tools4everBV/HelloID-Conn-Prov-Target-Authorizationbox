# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.1.0] - 2026-07-24

### Added
- Sub-permissions script for dynamic role assignment based on contracts in scope
- Retry logic for transient "active requests pending" errors across all lifecycle scripts
- UserValueSourcesModel built from current Authorizationbox user data to prevent field nulling


### Changed
- Field mapping simplified to Create and Update actions only (removed Delete/Disable mappings)
- Removed DisabledRoles field from field mapping
- Permissions revoke now validates against actual Authorizationbox roles before sending request

### Fixed
- Revoke correctly resolves company value from Authorizationbox when stored value is stale or empty

## [1.0.0]

### Added
- Initial release of HelloID-Conn-Prov-Target-Authorizationbox
- Account lifecycle: Create/Correlate, Update, Enable, Disable, Delete
- Permission management via static grant/revoke and dynamic sub-permissions
- Authorization request model with ProcessRequest support
- UTF-8 encoding for authorization request bodies
