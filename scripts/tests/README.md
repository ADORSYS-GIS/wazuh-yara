# Script testing

## Bash Automated Testing System (BATS)

The BATS framework is used to test the scripts in this project. The tests are written in the BATS language and are
located in the `scripts/tests` directory.

```bash
docker run --rm -it -v "$PWD:/app" bats/bats:latest /app/scripts/tests/test-script.bats
```