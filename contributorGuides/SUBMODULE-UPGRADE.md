# Submodule Upgrade
[![Project Version][version-image]][version-url]

---

## Upgrading the project submodules
1. Ensure that [Foundry][foundry-url] is installed and functioning properly
2. Pull the code from the [repository][repository-url]
   ````
   git pull [repository-url]
   ````
3. Issue command to update the submodules
   ````
   git submodule update –remote
   ````
4. Add any new files pulled from the repository to the Git index.
   ````
   git add .
   ````
5. Commit the new files
   ````
   git commit -m "Updated submodules using developer guide steps"
   ````
6. Push the changes back to origin
   ````
   git push
   ````

<!-- These are the body links -->
[foundry-url]: https://book.getfoundry.sh/getting-started/installation
[repository-url]: https://github.com/thrackle-io/forte-rules-engine


<!-- These are the header links -->
[version-image]: https://img.shields.io/badge/Version-2.2.1-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/forte-rules-engine