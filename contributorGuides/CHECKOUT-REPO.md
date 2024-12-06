# REPO CHECKOUT
[![Project Version][version-image]][version-url]

---

## Checking out the repository

1. Ensure that [Foundry][foundry-url] is installed and functioning properly
2. Navigate to your desired directory
   ````
   cd [desired-directory]
   ````
3. Pull the repository
   1. Clone the [repository][repository-url]
   ````
   git clone [repository-url]
   cd [repo-directory]
   git update-index --assume-unchanged .env
   ````
4. Build the project(this will also create all the submodules)
   ````
   forge build
   ````

## Upgrading Submodules

[Upgrade Submodules][upgradeSubmodules-url]


<!-- These are the body links -->
[foundry-url]: https://book.getfoundry.sh/getting-started/installation
[repository-url]: https://github.com/thrackle-io/forte-rules-engine
[upgradeSubmodules-url]: ./SUBMODULE-UPGRADE.md

<!-- These are the header links -->
[version-image]: https://img.shields.io/badge/Version-2.2.1-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/forte-rules-engine