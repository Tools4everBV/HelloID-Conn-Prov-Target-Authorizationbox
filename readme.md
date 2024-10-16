
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
| Application server information | Information containing information about the applicationserver such as instance name, powershell module path, but also dynamics tentant, permissions and languageID | Yes         | 


### Remarks
This connector requires specific configuration. Requirements are as followed:
Permissions can only be set through SubPermissions. Because Authorizationbox works with 'requests' that can be denied, HelloID must always check which permissions have been assigned to a user before setting up a request. Doing so, makes whatever is calculated by HelloID contracts 'the truth. Additional roles can not be set by hand, as these will appear in a 'remove' request every time the permissions is updated.

Because Authorizationbox only accepts requests that can be denied or approved, HelloID can not set permissions through Business Rules. Monitoring requests status can not be done through HelloID and this will lead to mismatched.

Only 1 request can be open at any time. There is example code added for updating authorization requests, but this does not work. Instead, we delete the old request and build a new one.

Organizational Units must be named exactly as in the source system

Functions must be named exactly as in the source system

If a combination can not be found, this connector will generate an error



#### Creation / correlation process

Users will currently not be created in AuthorizationBox. Instead this script creates or correlates a user account in Microsoft Dynamics 365 Business Central. It checks if the user already exists (correlates) or creates a new user, configuring necessary attributes like username, email, and permissions. Currently we do not compare the user, and will always update when a user is correlated.

This connector users the nav-tools powershell scripts that Business Central supplies.

> Be aware that this might have unexpected implications.

## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required. Like the _primary manager_ settings for a source connector.

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
