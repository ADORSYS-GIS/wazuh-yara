# Changelog

All notable changes to this project will be documented in this file.

## 0.4.0-rc.4 - 2026-02-27

[37bd5bb](https://github.com/ADORSYS-GIS/wazuh-yara/commit/37bd5bb413427d17cece20ecce3fbbde932f0cef)...[8666609](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8666609dde00d36402dda0d5e4f84ee7d0756b3c)

### Bug Fixes

- Updated fetch depth for git-cliff ([`8666609`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8666609dde00d36402dda0d5e4f84ee7d0756b3c))

### Miscellaneous Tasks

- Added automatic release notes and changelog generation ([`bc3aecc`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/bc3aecc55d0fe8b1d7491b3aab61fa1a78b29c6b))

## 0.3.14 - 2025-11-13

[798ddb6](https://github.com/ADORSYS-GIS/wazuh-yara/commit/798ddb693b493ee0e7095ab9b926437025ebd22e)...[37bd5bb](https://github.com/ADORSYS-GIS/wazuh-yara/commit/37bd5bb413427d17cece20ecce3fbbde932f0cef)

### Bug Fixes

- Remove deletion in yara-server.sh script ([`3782f3c`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3782f3c378d54daec6108563daa8aa51f38115e0))

## 0.3.13 - 2025-10-21

[96d23c3](https://github.com/ADORSYS-GIS/wazuh-yara/commit/96d23c38e0558df17be3b22260a6cb6f1684ec59)...[798ddb6](https://github.com/ADORSYS-GIS/wazuh-yara/commit/798ddb693b493ee0e7095ab9b926437025ebd22e)

### Miscellaneous Tasks

- Change yara.sh url for testing purposes ([`74d8a8a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/74d8a8a5cbfd5995ee110fa7b6542817ec452ce4))
- Update yara.sh url to main ([`798ddb6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/798ddb693b493ee0e7095ab9b926437025ebd22e))

## 0.3.12 - 2025-09-28

[9c54cb4](https://github.com/ADORSYS-GIS/wazuh-yara/commit/9c54cb4ed6846f96d7acfc784fc6c0977817e3ea)...[96d23c3](https://github.com/ADORSYS-GIS/wazuh-yara/commit/96d23c38e0558df17be3b22260a6cb6f1684ec59)

### Bug Fixes

- Point YARA_SH_URL to wazuh-yara repo ([`22bb5dd`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/22bb5dd9512dc32cbd4bbb6a1d0e9300894a601f))
- Consider arm architecture ([`3b4ab0d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3b4ab0dd5e5e16050021be16cd300eb3838c591a))
- Remove source built yara in install script ([`473d1a6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/473d1a618728fda08a671c5d5037f8bed751ac60))
- Add check to consider only supported distro's for linux ([`c3beb91`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c3beb9121301922cebcf196bf1061aedb5e18be2))
- Remove source built yara always running eben if installation is done using prebuilt ([`fd6a2e9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/fd6a2e92353e1c906e44ce5bf5fd9c2b2043c53d))
- Improve OS and distribution detection with unified approach ([`762ab46`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/762ab46c9cb70acde4038e6d61733b95e9aa6682))
- Use prebuilt binary built on older GLIBC version ([`882530a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/882530ae1a9572c846bca3d7fc308abd8c7ddc17))
- Yara prebuilt binary release tag ([`6dfce92`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/6dfce92df2a3b55169e6ecddedb9bdf8d83e531a))
- Use yum to install yara for centOS and RHEL ([`048cca9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/048cca92c4111da4d436d6dcd70b2b2af2b428c0))
- Build yara from source for centOS/RHEL if yum fails ([`a4901be`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/a4901beb3ab086b74f903176208d5dc442c41e00))
- Shellcheck issue line 896 ([`4270fdb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4270fdb5e7f8f825261ee0f17cdc4a7f3f64cd3f))
- Add required dependencies for building yara from source ([`01e25fd`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/01e25fdc6ffab968c2300127add1eca3bdc01c63))
- Libmagic devel does not exist ([`f2cf4aa`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f2cf4aa8b46cd75e9210fef49345a9589823bcfe))
- Include jansson dependency for source build ([`490c3af`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/490c3af6030cc2b4c5aec0402ca00652f96e3f98))
- Install jansson and libmagic for rhel ([`bfd051a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/bfd051aabccb398d624e6e9af6b6400097c52c12))
- Enable codeready-builder repo for RHEL 8/9 jansson-devel installation ([`7f678a1`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/7f678a14f2831ab088db9c1abec1bf7a967f3fb1))
- Quote to prevent splitting issues ([`b87d3eb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b87d3eb1f014f381ed88ad5ed02c2d9e6bfa3d78))
- Update verification step to check for yara v4.5.x ([`de6ccf8`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/de6ccf89537ea15af3ac9da673a4896ca27b6de1))
- Make notify send optional for centOS and RHEL ([`f11f37f`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f11f37f83030557d529e1ffc93c488ab4b6d5245))
- Make notify send optional for centOS and RHEL and fix shellcheck issue ([`39fd1d6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/39fd1d6506d094b8508094cb7d20d31093941030))
- Update uninstall.sh for centOS and RHEL ([`594516f`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/594516f41979627e95f1e8e8b92ab6db867c6280))
- Remove rpm based distribution ([`ddaba14`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ddaba14499df0ea3d1f2155070eecac89f7942e2))
- Remove rpm based distro functionality from uninstall.sh ([`c18e1e9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c18e1e98d4a646585a262078de166ce60ece9116))
- IconPath updated to correct path for macOS ([`430ea61`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/430ea61a20c8f59a2c0bc4eaa64cd8a181053795))
- Move loggin helpers before being called ([`d2b7390`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d2b73906350f2c951bc10371454363badf82a13e))
- Move logging helpers before being called ([`f2409b3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f2409b316adeb33bdbbb4c14ae66575351e9828e))
- Spelling error on wazuh iconPath ([`2b9c4f7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/2b9c4f73e2c48605353e720091f9b12a96c9e9c5))
- Remove unused function ([`12f9f17`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/12f9f1726e68b811c19361a2b8a9805ed91813f2))
- Enhance YARA uninstallation for Ubuntu by checking for prebuilt installations ([`e1e2b4a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e1e2b4a6af798a23858b3463041430913e4d79d9))
- Remove redundant cleanup logic for YARA prebuilt installation ([`224811d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/224811d46608931573066405b54b4614c00b1c4d))
- Remove local to use only POSIX features ([`b7188a5`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b7188a526c2bd01863368c097ce26afffada37ca))

### Features

- Add YARA server-side active response script for auto-deletion on detection ([`096af40`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/096af403af2bb567c0f030f8edd58c57641114a1))
- Add support for uninstalling YARA on RedHat-based systems ([`18a5c75`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/18a5c75ffea4df25588822c069c30ecb0902a77d))
- Add YARA uninstallation script for server OS ([`867952d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/867952d9695f393181dbcf82edc13d7fb3f369bd))
- Improve YARA binary detection and error handling ([`3ac9a97`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3ac9a9720000c1d73f004f089f1b96e24e050c52))
- Add check for prebuilt YARA installation during uninstallation for Ubuntu ([`9c7456a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/9c7456a14ab3ab7da60882a80521411509a0bd77))

### Miscellaneous Tasks

- Add ShellCheck workflow for scripts/install.sh ([`e1e0874`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e1e08748736a7829e276cb6cd665cc40ff946dbe))
- Remove ShellCheck workflow ([`5425aae`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5425aae8e7e3d41556371699ee0d7874f0842d33))
- Remove ShellCheck workflow and update install.sh ([`79f0096`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/79f0096e4f2fe13a46d98563b195da3db3ad388e))
- Remove ShellCheck workflow (correctly) ([`add27f6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/add27f6fec97daa1aad21833045b8e146d913ace))
- Refine Ubuntu prebuilt YARA install flow ([`bb1a160`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/bb1a160c93c3795450df6de71b43365cd7c5e531))
- Update url to yara-server.sh ([`96d23c3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/96d23c38e0558df17be3b22260a6cb6f1684ec59))

### Refactor

- Refactor: restructure install.sh with separate main functions for prebuilt vs source ([`7157a8b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/7157a8b7b35c4d3953d55ce40e7dc599e586c8bb))
- Streamline Wazuh agent restart and validation steps ([`b61ae72`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b61ae72ed4410b35cb9e337198c70049a404d753))

## 0.3.11 - 2025-09-18

[b4f34e8](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b4f34e8f8c5d3a575d628429c9f75b9d9b2530dc)...[9c54cb4](https://github.com/ADORSYS-GIS/wazuh-yara/commit/9c54cb4ed6846f96d7acfc784fc6c0977817e3ea)

### Bug Fixes

- Update YARA path detection for macOS to support prebuilt binaries ([`64e4090`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/64e4090e1f220e9e6d594746a5dcd71eb4b374a1))
- Improve YARA version detection to ensure prebuilt binary installation ([`01e6fa7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/01e6fa7f7a8a4870f555f02e1b895f014c8b9cf4))
- Correct YARA extraction path and Homebrew uninstall error handling ([`a8ec647`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/a8ec647fb07e21d745887a5c37dd4ec9fcefc641))
- Enhance YARA uninstallation process for macOS and improve symlink removal ([`fc206cd`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/fc206cdf7c93d97459dc18463e00a1ab23ffed79))
- Extract YARA binaries directly to /opt/yara without nested directory ([`63405a6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/63405a6f49be94204a9ad9880b1305be31ff04e1))
- Change ls to find ([`1c46396`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/1c4639687415a1bdf47fe9619e034bf75c9df2d0))
- Streamline YARA uninstallation process and remove macOS specific logic ([`8d5922d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8d5922d66bc5e225d2839ca0def1fcabd9651f60))
- Enhance YARA uninstallation for macOS with Homebrew support and improved logging ([`2a8f8fd`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/2a8f8fdac1f30eead27c790baf22f90cb197dea2))
- Improve YARA installation verification for macOS background services ([`0fda3ef`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/0fda3ef518b940403fd99672dd89669c78a711d6))
- Update validate_installation() to check direct path fallback ([`21dc79c`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/21dc79c276202c5c0ecbada9c7884fb905b2235c))
- Removed redundant yara installed validation step ([`627b85e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/627b85ea0934228227c380c37c5c09ed608551f8))

### Features

- Feat: replace Homebrew tap with prebuilt binary installation for macOS ([`1d8a72a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/1d8a72aba7a36f742c73fff45afba2e859e82225))
- Ensure YARA runtime dependencies remain installed on macOS ([`6fc7de7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/6fc7de7ecf88452620e048946eb80d1a858e1f2f))

### Refactor

- Simplify YARA path detection to use direct installation path ([`98f43f3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/98f43f3b9948780b27d16e5951f48b35aadab7a6))

## 0.3.10 - 2025-08-29

[d073a05](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d073a0549cdf2e5abf59ddd4c9c69c2b54e81545)...[b4f34e8](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b4f34e8f8c5d3a575d628429c9f75b9d9b2530dc)

### Bug Fixes

- Improve log messages to reflect success and error states for file operations in yara.sh ([`8aa961a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8aa961acd00c571eb3cf0fed4d457ebd3f45fbc9))
- Update uninstall and install functions for YARA to handle specific versioning in Homebrew ([`fd92664`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/fd92664336a0db3408eced015f2483cd5f205099))
- Unpin YARA before uninstalling via Homebrew to ensure proper removal ([`8a00a6b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8a00a6b0bc98ba19b93ed11c9451fd5ddaf35c3f))
- Improve install function on macos ([`3ea6b71`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3ea6b716abbce8e99f1f419a11bcbfec56495a1e))
- Unpin YARA before uninstalling via Homebrew to ensure proper removal ([`bc844cb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/bc844cbf58b8b148cc94436ec20b269ca413eb70))
- Remove duplicated unpin command ([`1a9d460`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/1a9d4600dff0544ce84aa701118c8c4b2b89aa76))
- Add Bash 4+ compatibility check to auto-detect and use newer bash on macOS/Ubuntu when root uses Bash 3.2 ([`96a4f8e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/96a4f8ec1972914cc5c573a5b82e22f7fd386225))

### Features

- Add check_and_update_bash function to ensure Bash is up to date on macOS ([`dc0d802`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/dc0d802c8724ac6c99323811e024a596ddbc43ed))

## 0.3.9 - 2025-08-25

[d14db88](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d14db8820240875a28f075d796fa30aacb17e9a6)...[d073a05](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d073a0549cdf2e5abf59ddd4c9c69c2b54e81545)

### Bug Fixes

- Install YARA via Homebrew tap on macOS ([`01983f7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/01983f7ed7246f014f4855f53ef013afe1fb1306))
- Enhance install_yara_macos function for Homebrew tap installation ([`998f838`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/998f8383ecc2ce6f2f09fae6fca92e684aff749b))

### Miscellaneous Tasks

- Update log messages to use INFO level for file operations in yara.sh ([`fe3fd31`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/fe3fd318ded34da1705af6864dea4d8c46c28d71))

## 0.3.8 - 2025-08-14

[55e7519](https://github.com/ADORSYS-GIS/wazuh-yara/commit/55e75192ee8548e4c729f5b98b3381afcc33b81f)...[d14db88](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d14db8820240875a28f075d796fa30aacb17e9a6)

### Bug Fixes

- Improve Homebrew detection and user handling ([`9ceb134`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/9ceb1345e57c5118ee34c28857e06d07db2459af))
- Add sudo flash to simulate initial login ([`0c80988`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/0c809883edbeae5106044005a0472f9aaf37df28))
- Remove -H flash parameter from sudo brew command ([`d12f9b4`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d12f9b476441e1ca0fdc8dfc137b3c3db17447c5))
- Use absolute paths to download yara from source ([`164bcc7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/164bcc73a243b5cf102f73423d60b4a0b2a36f04))
- Revert method of getting logged in user ([`ef4213e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ef4213e4de3a379bda48802a3543f5d05a7a6789))

### Testing

- Get logged in user using brew --prefix ([`c9aacac`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c9aacacac67de051a534f6346b40d0565100bc98))

## 0.3.7 - 2025-07-23

[f52f096](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f52f096b025de0c4f7a26531e0157b5a3f978f9a)...[55e7519](https://github.com/ADORSYS-GIS/wazuh-yara/commit/55e75192ee8548e4c729f5b98b3381afcc33b81f)

### Bug Fixes

- Enhance README for clarity on Windows Defender integration and cross-platform features ([`772d89d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/772d89d035fcb77b27864fe5cfafd65a3809e00e))

### Features

- Add Windows Defender integration script ([`11ebd4b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/11ebd4b8c19fc074b7885e23a4acf3c4cd04db6e))

## 0.3.6 - 2025-07-10

[ef3735f](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ef3735f09e3829aec66334a5cd3ad4bd965f43f1)...[f52f096](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f52f096b025de0c4f7a26531e0157b5a3f978f9a)

### Bug Fixes

- Replace maybe_sudo with sudo for Homebrew commands in install.sh ([`879f7ee`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/879f7ee13970c35db0d929842e283a7522fe0707))
- Ensure LOGGED_IN_USER is initialized before assignment in install and uninstall scripts ([`dc31479`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/dc31479f7c5e91b70b24a124692634a9c2ba5599))
- Update Wazuh agent installation script URL in yara-test workflow ([`bab4599`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/bab4599ed4bf3b0a60e6ced4b21d065ef1c5f535))
- Update Wazuh agent installation script URL to remove unnecessary refs ([`e111244`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e111244ca23b0da02bf95b934b50c202341c9fb0))

### Features

- Add function to get logged-in user for macOS and Linux ([`13dc335`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/13dc335c848bf7069d2744fce8c74191cbc8fd0b))
- Implement logged-in user retrieval for Homebrew commands in install and uninstall scripts ([`832ddfa`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/832ddfafde8ef8389a71d65cae4265cd804663ce))

## 0.3.5 - 2025-06-20

[48d0c44](https://github.com/ADORSYS-GIS/wazuh-yara/commit/48d0c442acfeb89c8c72f02f95e1e43e4d4acda9)...[ef3735f](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ef3735f09e3829aec66334a5cd3ad4bd965f43f1)

### Bug Fixes

- Add wazuh logo to all notifications where applicable ([`f02b35e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f02b35ec127fdee9b59876d54372ed2468294e30))
- Change log level from INFO to DEBUG for various messages ([`b8667b7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b8667b792cd986026708d1b6b953ded796997621))
- Remove type attribute from ignore tag in add_fim_ignore function ([`6913f7e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/6913f7eec76bc58856baa3f584de822e4fe7bbec))
- Update iconPath variable assignment for macOS and Linux environments ([`3101b3f`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3101b3f61ebf99070eb9c7865317698475de8f38))
- Change method to install yara on ubuntu machines from apt to source code installation & update yara.sh script correspondingly ([`e9b86e7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e9b86e7698e6fa431c1270391a04968866cb446d))
- Change macos yara install to install from source ([`74acc72`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/74acc728d8f6b487e4616f14c4b3052f960c2736))
- Add remove_brew_yara function ([`66a1898`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/66a1898a4d8977c76298134ccd4a37c3cc32eda4))
- Improve install and uninstall scripts for macos and ubuntu ([`a6aa62a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/a6aa62a5b82e7d279bae16997618019341cf5db9))
- Use maybe_sudo to cleanup temporary directory ([`6dda6cb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/6dda6cba8230f5b293a09ff5ad26788ff8fa1efc))
- Improve install script to install specific version of yara with brew on macos; update uninstall script to run only if yara is installed ([`5f22bf6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5f22bf69fb5fd5885bd5bc1ae28d06b07e1ed22f))
- Add all yara modules and required dependencies to install script ([`af639d3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/af639d3dc2a55297b483ebf123087ab4965e1f32))
- Update GitHub Actions workflow for pytest and enhance install script with notify-send checks ([`00fceda`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/00fceda9eee9ee21a30a9e2efd64b91a665b6081))
- Simplify ignore rule check in add_fim_ignore function ([`83eb9d6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/83eb9d68d25319c5112f21f6f6de17bda1577f4b))
- Install libnotify if necessary ([`3a46d42`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3a46d424be1e90dded3a8eaa1aaee9491e32cbce))
- Change ownership command to recursively update user and group for specified path ([`b72d233`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b72d23387338f7fe07be417381bc276357795816))
- Update group creation command for macOS to use sysadminctl ([`5627573`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/56275739d9b099a3dec6dfc1006ac5815ff22118))
- Update group creation command for macos ([`5994838`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5994838d6ec6c755e9149ff19bb86c54f8ba832c))
- Improve error handling for user and group creation on macOS ([`c591eec`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c591eec713d46173c4d17a897fabff4cd2b5c9f0))
- Update Wazuh agent installation method in yara-test.yml ([`76c9d64`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/76c9d647d5990b82d18bdbbd22afd0edfb60f68f))
- Update Wazuh agent installation script reference in yara-test.yml ([`1f3f8a4`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/1f3f8a44c90003731d3d4d64a88a118b23d5b05e))
- Remove unnecessary unit tests ([`a5c5452`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/a5c5452a2df1635c00c500a99d6269cf2657257b))
- Remove unnecessary unit tests ([`4a758f5`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4a758f5d5f862f99cc93294f7c77c5d5b8474039))
- Remove version extraction step from release job because it's depreciated ([`1316535`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/13165350b3b1adc4b693f22aeed862e0a51708ac))
- Fix automated release pipeline ([`ef3735f`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ef3735f09e3829aec66334a5cd3ad4bd965f43f1))

### Documentation

- Update README to enhance structure and clarity, add installation details, and improve usage guide ([`3572ee8`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3572ee8240887226c1c066af3fdc664835a05476))

### Features

- Update yara.sh with actions to delete malware files or ignore those files from future scans ([`d7a0ec1`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d7a0ec136099b5c49bd43534ca242d1bb2775fcb))
- Add success and failure notifications for file deletion and ignoring in yara.sh for macos ([`40ae3d9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/40ae3d9e5816b2875a8f3ae3696cca38553e8338))
- Add Zenity installation check and refactor YARA installation process ([`bb6df3b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/bb6df3b369c4182ce953b95ce3bad5dd5f590713))

### Miscellaneous Tasks

- Set yara version to 4.5.4 ([`8172740`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8172740ef798e6cdd0bbd9b50187dea85c83ab41))

### Refactor

- Enhance GitHub Actions workflow for pull requests and improve YARA test suite documentation ([`4a97da2`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4a97da25df8c5d92b743b941cd1bb6bbb0bb939a))

### Testing

- Add test for zenity installation on Linux ([`5ce8e26`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5ce8e2656426453432499994a140ead75ad9cd0b))

## 0.3.4 - 2025-05-14

[8b1b9a8](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8b1b9a8dcd18b7ab96552a279205809b138b37dd)...[48d0c44](https://github.com/ADORSYS-GIS/wazuh-yara/commit/48d0c442acfeb89c8c72f02f95e1e43e4d4acda9)

### Bug Fixes

- Improve how to extract rules and file path from yara results #33 ([`2004e4e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/2004e4e64eef9b3ff0a271622ddfaad2c00f9acb))

## 0.3.3 - 2025-04-28

[c8e3a65](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c8e3a652b508f6561d46a17fddd852cacb54fe98)...[8b1b9a8](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8b1b9a8dcd18b7ab96552a279205809b138b37dd)

### Bug Fixes

- Fix remove_file_limit not working on macos ([`62472c1`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/62472c1dda50bb6939bca69d436c2d5ec462c780))

### Miscellaneous Tasks

- Remove functions to update ossec.conf and add functions to revert to initial state ([`03182d3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/03182d3b9f86fa689aa1d98ea974f526fda1cc93))

### Testing

- Remove test function for fim content in ossec.conf ([`53c177b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/53c177b9e2f073476450a6d571fc673ad530ed7c))

## 0.3.2 - 2025-04-04

[5c8e48b](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5c8e48b53252c598467afe62e7106a35508fdcde)...[c8e3a65](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c8e3a652b508f6561d46a17fddd852cacb54fe98)

### Bug Fixes

- Change log file path to relative log file path ([`b0e0cbc`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b0e0cbccd868f41080f5e017e985970bb0d1b708))

## 0.3.1 - 2025-04-03

[15b47f8](https://github.com/ADORSYS-GIS/wazuh-yara/commit/15b47f8c992f788ff82dc7cece796f3d5acc64e7)...[5c8e48b](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5c8e48b53252c598467afe62e7106a35508fdcde)

### Bug Fixes

- Update yara rules and yara.bat script url ([`e2ad1f9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e2ad1f9134b0003c9a51185fd74780612ffccd83))

## 0.3.0 - 2025-03-25

[211d5e3](https://github.com/ADORSYS-GIS/wazuh-yara/commit/211d5e3f9957a1097d0d7e6f82c0f850ea40b13f)...[15b47f8](https://github.com/ADORSYS-GIS/wazuh-yara/commit/15b47f8c992f788ff82dc7cece796f3d5acc64e7)

### Documentation

- Added company copyrighht info in active-response scripts ([`368adc2`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/368adc239830abf07b9f1b19c150d3b974706ba1))

### Features

- Add notification on local host for yara results ([`490a840`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/490a840dafa274ea2381730e9f8ced964fd6fc9e))
- Add Notification function is launched using scheduled task ([`90920f0`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/90920f07f139154e338763dc448947a4fdb5a1c9))
- Add VBScript to run notification script without powershell popup ([`ef9ba2d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ef9ba2d9d724436bb31446d9a60640a54c75e8a7))

### Miscellaneous Tasks

- Fix notifications yara.sh ([`7e51b34`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/7e51b34a9e3ada679586326824e12c33cafb38ed))
- Remove unecessary functions from yara.sh ([`2203177`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/220317764b3e1744467b8d92a74b46e17cbd6e91))

### Refactor

- Improve format of display in active response notification on linux/macos ([`203242d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/203242da91a45fa0e31182d9ed5a5522ce1008fd))

### Testing

- Revert yara rules path to normal path ([`528e8d0`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/528e8d0477812bf4c266bf1783505bb08f897561))

### Enhance

- Update yar rules source to yara forge ([`7641db5`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/7641db5f2ff3649ddbf2697a118f50c3b9cbf428))

## 0.2.2 - 2025-02-18

[120cc63](https://github.com/ADORSYS-GIS/wazuh-yara/commit/120cc637f41244087eaa53625a4a487154b3890d)...[211d5e3](https://github.com/ADORSYS-GIS/wazuh-yara/commit/211d5e3f9957a1097d0d7e6f82c0f850ea40b13f)

## 0.2.0 - 2025-02-11

[18c6ea1](https://github.com/ADORSYS-GIS/wazuh-yara/commit/18c6ea16ea0a034c45dacf0a6985b4352d55331c)...[120cc63](https://github.com/ADORSYS-GIS/wazuh-yara/commit/120cc637f41244087eaa53625a4a487154b3890d)

### Bug Fixes

- Remove temporary files in temp directory ([`4179ca9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4179ca9081bbc9ef5cd5dfdb520a55718cea0b56))

## 0.1.2-rc3 - 2025-01-31

[620b305](https://github.com/ADORSYS-GIS/wazuh-yara/commit/620b305c3898955b8992a938a4fe5b3bd03e6f2a)...[18c6ea1](https://github.com/ADORSYS-GIS/wazuh-yara/commit/18c6ea16ea0a034c45dacf0a6985b4352d55331c)

## 0.1.2-rc2 - 2025-01-28

[5ee9b51](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5ee9b51003c45ad4e78e41f85413f88cea963bd2)...[620b305](https://github.com/ADORSYS-GIS/wazuh-yara/commit/620b305c3898955b8992a938a4fe5b3bd03e6f2a)

### Bug Fixes

- Change logging method ([`95473e0`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/95473e0332afd4eacd4a3c202a1ee667a8422858))
- Change function to remove environment variables ([`7f6d240`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/7f6d2405bfe1df8779d2c2d22fead44f32cb743d))
- Improve logging on Yara install script ([`c9fa618`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c9fa61809b3856bc54d48aa5c028f6800d6f9d3f))
- Calling logging correctly for cleanup ([`f917b5b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f917b5be387aed3f2df531f759a6c18d18f305d0))
- Yara rules temp directory ([`350734b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/350734b3536688e860a2c60c9dc85d8f3809f965))

### FIx

- Reduce FIM interval freqeuncy ([`60d3906`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/60d390638e84e7ddb8690342522fcaebfc8e411b))
- Reduce FIM interval freqeuncy for windows ([`dd2aa6a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/dd2aa6a487e62ca8d7448189a65921735bff3a45))

### Features

- Initial uninstall script for yara ([`c8bf184`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c8bf1848ef968b62c6f53f4268bfd67f2ae715d7))
- Update uninstall script ([`e992ad6`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e992ad6ea8ff39f8df964a37bc549c20ac58dc0a))

### Miscellaneous Tasks

- Improve how to set yara path in tha active response script ([`f58d708`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f58d708c0ae781b1c9d14930f21c57c34b34771f))
- Improve how to set yara path in tha active response script ([`a725429`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/a7254296053d9be925b3abcb062d9b02e784d9fb))
- Remove ineffectual variables ([`f0fc89b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f0fc89b9c277f7165297d4076025533923312696))
- Update folders to monitor ([`7f67aeb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/7f67aeb85f53002002b48d510d52e0d37e1ea984))
- Update tests ([`fe0cdae`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/fe0cdaeb80a52115c6521f1ab4d65f383e18fa2e))

### Fic

- Check if Service exists & improving logging ([`b8f77c0`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b8f77c08e20e61679c5663d64044c9cb79766784))

## 0.1.2-rc1 - 2025-01-28

[368d8c3](https://github.com/ADORSYS-GIS/wazuh-yara/commit/368d8c3e7f410fcca822647adf3a91312783ee3a)...[5ee9b51](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5ee9b51003c45ad4e78e41f85413f88cea963bd2)

### Bug Fixes

- Improve logging in yara.sh ([`5ee9b51`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5ee9b51003c45ad4e78e41f85413f88cea963bd2))

## 0.1.1 - 2025-01-25

### Add

- Yara.bat script file ([`982f387`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/982f3876544ed1c0f3a091e6e4ab141dc9cb9216))
- Malware_rules.yar file ([`61ae0fe`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/61ae0fee3217704740ee44593bb9b2e01e0534a9))

### Bug Fixes

- Ci ([`6f14f29`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/6f14f29d4aa2a74970bbad3d7c9c60e45553983f))
- Ci ([`4f77ae7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4f77ae7e3ee92447d175ebe50d493a3ec08ae55b))
- Add value of ossec conf path ([`2baa3d7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/2baa3d7b4b27b2afc8410012c4149eec9bb218dd))
- Handle `sed` command compatibility for macOS and Linux ([`398c2e9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/398c2e955ccb3fbae627d581145d5102e5fd92c2))
- Handle `sed` command differently for macOS and Linux in `check_file_limit` function ([`5141fde`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5141fde791a845ff9ee4b21d0804cd62e8bbd09d))
- Fix: use warn_message instead of error_message for missing config file ([`0c8832a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/0c8832a186457bc3a6afcecf34ea93779114bb3a))
- Encoding error yara.bat file ([`e3eabbb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e3eabbb0356c906155f7da54848780c686384657))
- Update yara rules directory fixed to path into rules folder ([`ce26b50`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ce26b50c936334a475d4b1d952e62312b12b8d8f))
- Double square brackets in files/directory checks ([`5f5a099`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5f5a09987a9b138bbe9d400950264795dded632b))
- Uninstall yara only if it exists ([`a5d5115`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/a5d51159737d61938472fa29320720f391ffd75e))
- MacOS not recognising /n as next line when editing config file ([`d4f3674`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d4f36747506857bcea25c98f70beb703608a7574))
- Update new line sed command to use // instead of /n ([`8864290`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/886429046c4a46c9962f3b4c6be6c7c54d26a804))
- Remove unneeded stop agent function and improved restart agent function in uninstall script ([`d0a4677`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d0a467726fda8ee4232e11f96f916f29b68f4498))
- Improve sed command usage ([`90cb965`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/90cb965bd7cac762af22435fe44ff05d4be1ce24))

### Chore

- Update Scripts to download rules/malware_rules.yar ([`599e7c3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/599e7c3b5e2cbd63bf25e41e91cfa9bae2752761))

### Documentation

- Update README file ([`84f2fbb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/84f2fbbb60a4e2b4165b9193e85ccb0e3bac4464))
- Improve active responses script to work on both linux and macos ([`60bd299`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/60bd2996e14e45c97c0e591d01ce7a33c3377539))

### Features

- Cd build (#2) ([`d4bd278`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d4bd278537ecd2f8c51f9e6f0dd5b5fef65f7911))
- Add GitHub Actions workflow for running Pytest ([`e76c597`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e76c59710bf5bbc36532e774aa7ca2b272b0d921))
- Add uninstall script ([`d41f875`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d41f87565d3a0ac8f6d04fc3fa005641dd15d4ed))
- Add uninstall script ([`d9bda9e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d9bda9e63b8ec7146015e137484251bce9dbe203))
- Add uninstall script ([`92e2c67`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/92e2c67de5e361c6f35c120b908118454356e275))
- Add installation validation steps ([`b89af7f`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b89af7f072371ed97003ad1f19f73223e3c84c45))

### Fix

- Removed lines that call deleted functions ([`0c8defb`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/0c8defb7f30369ea3c84d5a0c58c45f585df1107))
- ValhallaAPI try catch was not working because pip does not throw an error ([`fc2993b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/fc2993b0764eacd9a66e74e497f0ae87a71ccbff))
- Check pip module function fixed ([`e8e271e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e8e271e2f492445d0788740a8a9ebb7427fd3901))
- Fixed download yara rules script to save yara_rules to temp directory ([`e6b2b2f`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e6b2b2f0f246a7fd4fe946a92c8218eafd82ce00))
- YaraUrl used instead of YaraBatUrl ([`3b6fbe7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3b6fbe7ff4094947c9cd48b36c4cad9edeadbea9))
- Naming of yaraBatURL ([`40f3f72`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/40f3f7245bff413fe3ca2b8afa5c2677ceca8220))
- Naming of filelimitnode variable ([`16b4141`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/16b414196776d620849de020e3498d0034aa2a55))
- Correct file_limit node selection in syscheck XML parsing ([`4acf681`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4acf681b6e853589f8b5fedac9bb0708754cefaf))
- Naming of rules file ([`ec02409`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ec024091c71ea7f1d6894234e8928815a22b9828))
- Yara rules directory path was set to file instead of location ([`fa5f685`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/fa5f685fa7ce923c9ca80d8f5e0c6bdf741833a8))

### Miscellaneous Tasks

- Initial commit ([`212c36e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/212c36e0ec8222a27ea3531301472d01cee71e2e))
- Script; tested using docker ([`9f111cd`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/9f111cd0a80545379001712a4dbaf1934e67bc08))
- Typo ([`0655cab`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/0655cab818ae1168b11247d424366ac8853c35ec))
- Custom sed ([`1fdb6d5`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/1fdb6d54212ad8c33066ac1ea878053399a7fe73))
- File limit ([`0f7226a`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/0f7226a480460197d66bc0c9e0e00f2a82c0f79c))
- Moved script tests into script folder ([`823b282`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/823b2828d369165e821f917fc9e35fccf04bb37d))
- Testing using bats ([`956fbaa`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/956fbaa874d160ab43aac1076042335816313dea))
- More colors to the bash script ([`012c717`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/012c7178acc51975cf390eabf204bb6a1896fc46))
- Remove obsolete script tests and workflows ([`cb2283f`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/cb2283f25d91cd14d1c641c5fd601a0a7e3f4b7e))
- Update wazuh-agent installation and add yara test script ([`c2da7b7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c2da7b75645322693275ea75c808995cfdab5d91))
- Update wazuh-agent installation and add yara test script ([`cf48a9d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/cf48a9d9d2bec841a58968d7044cd24698a3bf91))
- Ensure yara_rules.yar file exists and has correct ownership ([`e724dcf`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e724dcfef3b0c815bbbfe173b1f53a4a9a5c532a))
- Fix yara_rules_file.exists() assertion in yara.py test ([`b061b31`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/b061b31c3dcbcaa2a0eade4e0ebb7a3e7fd016f5))
- Ensure yara rules file exists and has correct ownership ([`d5d470b`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d5d470bf8341d0547315ef25567d829e94e9201b))
- Update wazuh-agent installation and add yara test script ([`0de8c18`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/0de8c187b752c4894e501b147001530cd8f00a50))
- Update wazuh-agent installation and yara tests ([`68e074c`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/68e074ce45fc2cb1091199dd71426fa5efbbabbd))
- Update GitHub Actions workflow for running Pytest ([`746e292`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/746e292f261fe697c78d3d85db40a2f646f9433a))
- Update YARA Tests documentation and GitHub Actions workflow ([`5146af3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/5146af303a98fd9fab4007f668d932eb620f4c5b))
- Create user and group on macOS in install.sh ([`88cb9e9`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/88cb9e9b1a746030d49e6253eae185a3343b5a48))
- Improve error handling and OS compatibility in install.sh ([`38f4b17`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/38f4b17bccf01ad912bcb21d059c79cc0a1868da))
- Improve error handling and OS compatibility in install.sh ([`666caac`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/666caac8bff53275f1dd49b06552228d6ca82bf3))
- Update OSSEC configuration handling in install.sh ([`c68a63e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/c68a63eafebf2a66b6bc69628b7ab43f437ce207))
- Update OSSEC configuration handling in install.sh ([`62c6457`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/62c6457a49e1bf4f17d9163b063cac2c5ce6698f))
- Restart Wazuh agent in install.sh ([`1c9ad86`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/1c9ad864df86c80f91fe5ae7bbb8a888c7e8bc7b))
- Update OSSEC configuration handling in install.sh ([`13acf09`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/13acf0977e9f1980f90a93295adbd247428ba66b))
- Update Rules github link ([`095a814`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/095a814f63b7d45f80872c3c97b973201226a438))
- Save yara_rules.yar on correct directory on MacOS ([`e99216c`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/e99216cc9c4dce1c828efb41690d326fe9cc3425))
- Update yara rules url ([`aaaf065`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/aaaf065c364596c34ac069bd18900f928ad58d71))
- Add success message at end of script ([`05b3648`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/05b36486d308f01f92630a52080d577cf53025c8))
- Remove the installation of additional packages ([`6143c87`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/6143c874f933b69d7be90ebd64411287dd99009c))
- Improve idempotency in bash uninstall script ([`078ad80`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/078ad80f4ea8dfca25664fc954d9f738edbaceae))
- Improve idempotency in bash uninstall script ([`3e6f568`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/3e6f56835e7bfb1f93e1e4b369e61ed1156e89f0))
- Improve idempotency in bash uninstall script ([`ace63da`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/ace63da304917de2b8ecee29b8e33b800f986a1d))
- Improve logging in uninstall script ([`368149e`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/368149e8a2f9f36fff65b34a3793d4cfe5ac73f4))
- Remove configs in uninstall script, only if ossec config file exist ([`4546b05`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4546b05c00c4146a95361c2a88d1734e5da898df))
- Install yara if not already installed ([`7512fd8`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/7512fd852cb6f2d8df490ed4e543927a537040be))
- Add timestamp and colors to active response script ([`6dbe152`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/6dbe1523ab6c445d01c99d0eda09aa587592147c))
- Remove timestamp and colors from active response script ([`8a55728`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/8a55728b6648e7c97fe211320af4589c876bddd4))
- Update files to monitor on macos ([`42f42f1`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/42f42f12ce53718167cad5fbe70ea6748fce4a6e))
- Add release pipeline ([`368d8c3`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/368d8c3e7f410fcca822647adf3a91312783ee3a))

### Refactor

- Improve YARA installation and configuration process #3 ([`30fff69`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/30fff691cda93c3aedc123808c64bef322279768))
- Improve YARA installation process for Windows #3 ([`f3d444d`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f3d444d38825197ce8c5d72ecd689ac596405ba2))
- Improve YARA installation process for Windows ([`dde36e8`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/dde36e8f3076c524b975eab02c54d482ad111fd6)), Closes #3
- Improve YARA installation process for Windows ([`4dcddd7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4dcddd7083ac831e4e4d160511752eecaf328ce2))
- Improve YARA installation and configuration process ([`d322344`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/d322344d50f615bb669b692cf117f67796bab302))
- Improve log messages ([`75cd165`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/75cd16518ebc3e1c89d0a9065fdb4a2bdcc3b81f))

### Revert

- Yara.bat script added in this script ([`76e3ef7`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/76e3ef7150017afeedba8c7b8c0e71d33fb4facb))

### Testing

- Add maybe_sudo infront of file checks ([`1b289be`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/1b289befc6139ae897e9fc0962a0ec34f8336f8c))

### Update

- Removed dependecy installation from install.ps1 and added yara.bat installation ([`4a28d93`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/4a28d930528d563f62e8f1d313bf166d7d11f9c0))
- Moved yara.bat script to seperate file ([`df8b268`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/df8b268c33309fb095593104521189f00f99ec92))

### Revert

- Change rules file name back to yara_rules.yar ([`f2b0f77`](https://github.com/ADORSYS-GIS/wazuh-yara/commit/f2b0f776212ccedaaa64978333e868d0ce544cb5))

<!-- generated by git-cliff -->
