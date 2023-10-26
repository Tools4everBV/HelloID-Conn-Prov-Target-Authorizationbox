
# HelloID-Conn-Prov-Target-Authorizationbox

| :warning: Warning |
|:---------------------------|
| Note that this connector is "a work in progress" and therefore not ready to use in your production environment. |

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

| :information_source: Information |
|:---------------------------|
| This connector must be used in conjunction with the [HelloID-Conn-Prov-Target-DynamicsEmpire](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-DynamicsEmpire) connector |

## Table of contents

- [Introduction](#Introduction)
- [Getting started](#Getting-started)
  + [Connection settings](#Connection-settings)
  + [Remarks](#Remarks)
- [Setup the connector](@Setup-The-Connector)
- [Getting help](#Getting-help)
- [HelloID Docs](#HelloID-docs)

## Introduction

_HelloID-Conn-Prov-Target-Authorizationbox_ is a _target_ connector. Authorizationbox provides a set of REST API's that allow you to programmatically interact with its data. The connector correlates and updates the user.

The following lifecycle events are available:

| Event  | Description | Notes |
|---	 |---	|---	|
| create.ps1 | Update and correlate an Account | - |
| update.ps1 | Update the Account | - |
| entitlements.ps1 | Updates all entitlements | - |


## Getting started

### Connection settings

The following settings are required to connect to the API.

| Setting      | Description                             | Mandatory   |
| ------------ | -----------                             | ----------- |
| UserName     | The UserName to connect to the API      | Yes         |
| Token        | The Token to connect to the API         | Yes         |
| Database     | The Database where the users are stored | Yes         |
| BaseUrl      | The URL to the API                      | Yes         |


### Remarks
> The connector does not execute a 'create' request when the user does not exist. Instead, you need to create the user in Empire.

> The connector uses dynamic permissions (subpermissions). Create a static permission to grant the entitlements.

> During the development of the connector, we made the assumption that the entire organization role array needs to be sent when updating an authorization in the entitlement.ps1.

#### Creation / correlation process

A new functionality is the possibility to update the account in the target system during the correlation process. By default, this behavior is disabled. Meaning, the account will only be created or correlated.

You can change this behavior in the configuration by setting the toggle for `$updatePersonOnCorrelate` to checked.

> Be aware that this might have unexpected implications.

## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required. Like the _primary manager_ settings for a source connector.

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
