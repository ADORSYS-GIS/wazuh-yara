# Script testing

This folder is to run IT test for the scrips written above.
Tests are written using docker

```bash
TARGET_OS=ubuntu
docker build -f tests/$TARGET_OS/Dockerfile .
```
