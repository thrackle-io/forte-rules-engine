# Forte Rules Engine

[![Project Version][version-image]][version-url]

This repository contains an EVM-based protocol designed to meet the unique needs of tokenized assets and on-chain economies. The protocol enables the creation and management of economic and compliance controls for your on-chain economy at the token level, allowing for maximum flexibility while maintaining the transparency and trustlessness of Web3.

[version-image]: https://img.shields.io/badge/Version-2.2.1-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/forte-rules-engine

There are two ways most projects may utilize the protocol. 
1. 

## Installation

To install the package, run the following command in the root of your project:

```bash
npm i @thrackle-io/forte-rules-engine
```

### Dependencies

> numbered releases assigned to unmodified upstream binaries.

This package requires the following:

1.  Foundry

    NOTE: In order to ensure full support, run this command to get the correct Foundry version:

> [!NOTE]
> Thrackle maintains a modified [`foundryup`](https://github.com/thrackle-io/foundry/tree/master/foundryup) tool 
> to provide versioned releases assigned to releases of unmodified upstream binaries.

```bash
foundryup --version $(awk '$1~/^[^#]/' script/foundryScripts/foundry.lock)
```
 
2.  Scripting Requirements
    1.  `eth-abi 5.1.0`
    2.  `jq 1.6.0`
    3.  `python-dotenv 1.0.1`

    These packages can be installed manually or through the following helper command:

```bash
pip3 install -r requirements.txt
```

1. `@openzeppelin/contracts` version 4.9.6 and `@openzeppelin/contracts-upgradeable` version 4.9.6.

    If the contracts show any compiling errors, try to manually update the version of the existing openzeppelin library in your project by doing:

```bash
forge install OpenZeppelin/openzeppelin-contracts
```

```bash
forge install OpenZeppelin/openzeppelin-contracts-upgradeable
```

## Usage

### User Guides

For complete usage information and documentation, please visit the docs at https://docs.forterulesengine.io.

### Example Application

To deploy the Forte Rules Engine and an example application, follow the [deployment guides](https://docs.forterulesengine.io/deployment/overview). 

## Contributing

Please visit our [Contributor Guide](./CONTRIBUTING.md).

## Forte x Thrackle

Forte’s work is aided and supported by our ecosystem partner, Thrackle, a team of industry experts, including PhD-level engineers specializing in computer science, math, engineering, economics, and finance. Thrackle leverages its deep technical expertise to develop purpose-built, customizable products that enable the creation, growth, and stability of thriving digital asset economies. Together, Forte and Thrackle are driving innovation to build healthy, sustainable blockchain economies.

## Licensing

The primary license for Forte Protocol Rules Engine is the Business Source License 1.1 (`BUSL-1.1`), see [`LICENSE`](./LICENSE). However, some files are dual licensed under `GPL-2.0-or-later`:

- All files in `src/example/` may also be licensed under `GPL-2.0-or-later` (as indicated in their SPDX headers), see [`src/example/LICENSE`](./src/example/LICENSE)

### Other Exceptions

- All files in `lib/` are licensed under `MIT` (as indicated in its SPDX header), see [`lib/LICENSE_MIT`](lib/LICENSE_MIT)
- All files in `src/example/` may also be licensed under `GPL-2.0-or-later` (as indicated in their SPDX headers), see [src/example/LICENSE](src/example/LICENSE)
Other Exceptions
- All files in `contracts/test` remain unlicensed (as indicated in their SPDX headers).