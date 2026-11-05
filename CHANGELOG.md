# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.1.0] - 2026-11-05

### Added
- Sub-permissions script for dynamic role assignment based on contracts in scope
- Support for a company or a company group (`$DefaultCompany` / `$UseCompanyGroup`) in the grant, revoke and sub-permissions scripts
- Retry logic for transient "active requests pending" errors across all lifecycle scripts
- UserValueSourcesModel built from current Authorizationbox user data to prevent field nulling

### Changed
- Field mapping simplified to Create and Update actions only (removed Delete/Disable mappings)
- Removed DisabledRoles field from field mapping
- Disable no longer removes roles from the user (the commented example has been removed)
- Removed `AlwaysSendAutorisationRequest` from the update script
- Roles of a user are now retrieved by the immutable user key (`userCode`) instead of `userName`
- Permissions revoke now validates against actual Authorizationbox roles before sending request
- Grant and revoke only match a role in Authorizationbox on the same scope (company / company group); for sub-permissions this is the scope stored in the entitlement reference. There is no fallback to another company anymore
- On a sub-permissions revoke, roles are no longer looked up for the contracts in scope
- Messages and comments translated to English
- Removed commented code and logging of request bodies and field values

### Fixed
- Sub-permissions skipped grants and revokes when a user had two or more permissions (`ContainsValue` on a list)
- Sub-permissions role lookup now escapes single quotes and URL-encodes the OData filter
- Create now stops with an error when correlation is not configured
- Grant retrieved the profileId of an arbitrary role on the first role assignment (invalid OrganizationRole URI)

## [1.0.0]

### Added
- Initial release of HelloID-Conn-Prov-Target-Authorizationbox
- Account lifecycle: Create/Correlate, Update, Enable, Disable, Delete
- Permission management via static grant/revoke and dynamic sub-permissions
- Authorization request model with ProcessRequest support
- UTF-8 encoding for authorization request bodies
