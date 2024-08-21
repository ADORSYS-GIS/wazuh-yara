# Script testing

## Bash Automated Testing System (BATS)

The BATS framework is used to test the scripts in this project. The tests are written in the BATS language and are
located in the `scripts/tests` directory.

```bash
docker run --rm -it -v "$PWD:/app" ghcr.io/stephane-segning/bats-docker:alpine-latest bats /app/scripts/tests/test-script.bats
```