# HelloID-Conn-Prov-Target-Authorizationbox

<!--
** for extra information about alert syntax please refer to [Alerts](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#alerts)
-->

> [!WARNING]
> This connector is a work in progress and may require adjustments before production use.

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible for obtaining connection details such as username, token, and base URL. You may need agreements with the supplier. Coordinate with the client’s application manager.

> [!NOTE]
> This connector is designed to be used together with the [HelloID-Conn-Prov-Target-DynamicsEmpire](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-DynamicsEmpire) connector.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Authorizationbox/blob/main/Icon.png">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Authorizationbox](#helloid-conn-prov-target-authorizationbox)
  - [Introduction](#introduction)
  - [Supported Features](#supported-features)
  - [Getting Started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection Settings](#connection-settings)
    - [Correlation Configuration](#correlation-configuration)
    - [Field Mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Requests and Sub-Permissions Model](#requests-and-sub-permissions-model)
    - [Creation/Correlation via Business Central](#creationcorrelation-via-business-central)
  - [Development Resources](#development-resources)
    - [API Endpoints](#api-endpoints)
  - [Getting Help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Introduction
HelloID-Conn-Prov-Target-Authorizationbox is a target connector for Authorizationbox’s REST APIs to manage user authorizations. It correlates and updates users, and submits new authorization requests only (no request updates or status tracking). It is intended to be paired with DynamicsEmpire or DynamicsEmpire Cloud to synchronize user presence and security identifiers.

## Supported Features

The following features are available:

| Feature                                   | Supported | Actions                              | Remarks                  |
| ----------------------------------------- | --------- | ------------------------------------ | ------------------------ |
| **Account Lifecycle**                     | ✅         | Create/Correlate, Update, Enable, Disable, Delete | Enable/Disable currently do not work via the API; see Remarks |
| **Permissions (SubPermissions)**          | ✅         | Permissions & Sub-permissions         |                          |
| **Resources**                             | ❌         | -                                    |                          |
| **Entitlement Import: Accounts**          | ❌         | -                                    |                          |
| **Entitlement Import: Permissions**       | ❌         | -                                    |                          |
| **Governance Reconciliation Resolutions** | ❌         | -                                    | Not supported            |

Governance Reconciliation is not supported.

## Getting started

### Requirements

- Admin user with API key in 2control. (This can cost an extra license, see: https://wiki.2-controlware.com/en/AB-Setup_Administration#authorization-on-swagger)

### Connection settings

The following settings are required to connect to the API.

| Setting                | Description                                                                 | Mandatory |
| ---------------------- | --------------------------------------------------------------------------- | --------- |
| `UserName`             | Username for the Authorizationbox API                                       | Yes       |
| `Token`                | API token for Authorizationbox                                              | Yes       |
| `Database`             | Database/context where users are stored                                     | Yes       |
| `BaseUrl`              | Authorizationbox API base URL                                               | Yes       |

### Correlation configuration

Match an existing Authorizationbox user to a HelloID person.

| Setting                   | Value                                                     |
| ------------------------- | --------------------------------------------------------- |
| Enable correlation        | `True`                                                    |
| Person correlation field  | `Empire - userSecurityId`                                 |
| Account correlation field | `userSecurityId`                                          |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

You can import the field mapping using the `fieldMapping.json` file. `FullName` is always required. Ensure all fields used by Authorizationbox requests are properly mapped to avoid nulling behavior (see Remarks).

### Account Reference

Store the combined reference required by Authorizationbox/DynamicsEmpire (for example: `SecurityID|FullName|Username`). Changing this after correlation can break Authorizationbox request logic.

## Remarks

- Authorizationbox processes authorizations via requests that can be approved or denied; only one request can be open at a time. In standard usage, HelloID submits requests with `ProcessRequest = $True` so they are automatically processed. If you set this to false, you may encounter errors in HelloID when another request is still open.

- Fields not included in a request are currently nulled by Authorizationbox. A fix has been requested from 2-Control. As a workaround, include all relevant fields for each request via field mapping. Adjust your permission scripts accordingly.

- Enabling and disabling users does not currently work via the API. Flags are not set despite end dates and parameters. A fix has been requested from 2-Control.

- Because the workflow is request-based, comparing against a previous account state during request execution is not possible. Update statements have to be configured manually

- In the Disable step, roles are removed. In the Delete step, the user is closed (not hard-deleted). Fully deleting users can cause issues in DynamicsEmpire; therefore, we disable users instead. Hard deletion is possible but may cause problems during reboarding.

### Creation/correlation via Business Central

- Users are not created directly in Authorizationbox; the connector correlates or creates users in Microsoft Dynamics 365 Business Central (via nav-tools PowerShell) and updates Authorizationbox accordingly through authorization requests.

## Development resources

### API endpoints

- Public API documentation (AuthorizationRequests): https://api.2-controlware.com/authorizationrequest/swagger/index.html
- Public API documentation (OData stream): https://api.2-controlware.com/swagger/index.html


## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/

