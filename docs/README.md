# Documentation maintenance

This repository has two types of documentation:
1. Manually generated - this is the documentation that is written by hand
2. Auto-generated - this is the documentation that is generated by the code

## Manually Generated Documentation
The manually generated documentation root can be found [here][userGuide-url].

## Auto-generated Documentation
This repository utilized Foundary documentation generation for files using NatSpec comments. The commands to generate this documentation and to keep them up to date are:
(Note: This is currently performed by CI/CD processes and not manually run.)
The root of the documentation can be found [here](./src/SUMMARY.md).
```
foundryup
forge doc
```

<!-- These are the body links -->
[userGuide-url]: ./userGuides/README.md
<!-- These are the header links -->
[version-image]: https://img.shields.io/badge/Version-2.2.0-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/forte-rules-engine
