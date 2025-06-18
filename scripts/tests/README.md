# Project Testing Guide

This README explains the tests provided in the `tests` directory, how to run them, and why they are necessary. The tests focus on ensuring that Wazuh and its related components, such as YARA, are correctly installed and configured on the system. We also provide a GitHub Action for automating the test execution on every push or pull request.

## Prerequisites

The tests are written using `pytest` and `pytest-testinfra` to interact with the system's infrastructure. Make sure you have the following dependencies installed:

- Python 3.9+
- `pytest`
- `pytest-testinfra`
- Wazuh agent
- YARA (for malware detection)

## Installing Dependencies

To install the necessary Python dependencies, run:

```bash
pip install pytest pytest-testinfra
```

To install Wazuh and YARA, follow the steps outlined in the GitHub Action provided later in this README.

## Running the Tests

Run the tests with the following command:

```bash
pytest -vv scripts/tests/yara.py
```

## YARA/Wazuh Testinfra Test Suite

This directory contains automated tests for verifying the installation and configuration of YARA and Wazuh agent, as performed by the `install.sh` script. These tests are designed to be run with [pytest](https://pytest.org/) and [testinfra](https://testinfra.readthedocs.io/).

### What is tested?

- **User and Group**
  - The `root` user exists
  - The `wazuh` group exists

- **Wazuh Configuration**
  - The Wazuh configuration file exists at the correct path for the OS

- **YARA Installation**
  - YARA is installed from source and is version `4.5.4`
  - The `yara` package is installed

- **notify-send Version (Linux only)**
  - The `notify-send` binary exists and is version `0.8.3`

- **YARA Script and Rules**
  - The YARA active response script exists at the correct path, is owned by `root:wazuh`, and has mode `750`
  - The YARA rules file exists, is a regular file, and is owned by `root:wazuh`
  - The YARA rules directory exists, is a directory, and is owned by `root:wazuh`

- **Wazuh Agent Service**
  - The `wazuh-agent` service is running and enabled

### Explanation of Each Test

#### 1. **`test_user_exists`**
   - **Description**: Verifies that the `root` user exists on the system.
   - **Reason**: The `root` user is crucial for administrative tasks, and its absence might indicate misconfigurations.

#### 2. **`test_group_exists`**
   - **Description**: Ensures that the `wazuh` group exists.
   - **Reason**: The Wazuh agent needs to operate under this group for proper permissions management.

#### 3. **`test_ossec_conf_exists`**
   - **Description**: Checks if the `ossec.conf` file exists, which is the main configuration file for Wazuh.
   - **Reason**: The Wazuh agent cannot function without its configuration file. This test supports multiple operating systems.

#### 4. **`test_yara_installed_from_source`**
   - **Description**: Verifies that YARA is installed from source and checks its version.
   - **Reason**: Ensures that the correct version of YARA (4.5.4) is installed for compatibility and functionality.

#### 5. **`test_notify_send_version`**
   - **Description**: Checks the presence and version of the `notify-send` binary (Linux only).
   - **Reason**: Ensures that the notification system is available and functioning on Linux systems.

#### 6. **`test_yara_script_downloaded`**
   - **Description**: Ensures the YARA active-response script is downloaded and has the correct permissions.
   - **Reason**: This script is essential for active malware response, so its presence and permissions are crucial.

#### 7. **`test_yara_script_permissions`**
   - **Description**: Checks the permissions and ownership of the YARA script.
   - **Reason**: Ensures that the script has the correct permissions (`750`) and is owned by `root:wazuh` for security.

#### 8. **`test_yara_rules_file_exists`**
   - **Description**: Confirms that the YARA rules file exists.
   - **Reason**: YARA rules are essential for detecting malware, so this file must exist.

#### 9. **`test_yara_rules_file_permissions`**
   - **Description**: Checks the permissions and ownership of the YARA rules file and directory.
   - **Reason**: Ensures proper permissions and ownership to maintain system security and integrity of the rules.

#### 10. **`test_wazuh_agent_restarted`**
   - **Description**: Checks if the Wazuh agent service is running and enabled.
   - **Reason**: The Wazuh agent must be actively running to monitor the system.

### Running the tests

1. Ensure you have [pytest](https://pytest.org/) and [testinfra](https://testinfra.readthedocs.io/) installed:

   ```sh
   pip install pytest pytest-testinfra
   ```

2. Run the tests from the project root:

   ```sh
   pytest -vv scripts/tests/yara.py
   ```

### Notes

- The tests are cross-platform and will skip OS-specific checks as appropriate.
- Paths and permissions are checked for both Linux and macOS.
- The tests assume the install script has been run and the system is in the expected post-install state.
- The notify-send version test only applies to Linux systems.

## Test Coverage Map

| Test Name                        | What it checks                                 |
|----------------------------------|------------------------------------------------|
| test_user_exists                 | root user exists                               |
| test_group_exists                | wazuh group exists                             |
| test_ossec_conf_exists           | Wazuh config file exists                       |
| test_yara_installed_from_source  | YARA binary is present and version is 4.5.4    |
| test_notify_send_version         | notify-send is present and version is 0.8.3    |
| test_yara_script_downloaded      | YARA script exists, owned by root:wazuh, 750   |
| test_yara_script_permissions     | YARA script permissions/ownership              |
| test_yara_rules_file_exists      | YARA rules file exists and is a file           |
| test_yara_rules_file_permissions | YARA rules file/dir permissions/ownership      |
| test_wazuh_agent_restarted       | wazuh-agent service is running and enabled     |

## GitHub Actions Workflow

The GitHub Actions configuration (`.github/workflows/pytest.yml`) is designed to run the tests automatically on every push or pull request. It performs the following steps:

1. **Checkout the code**: The repository is cloned into the runner.
2. **Set up Python 3.9**: Ensures the correct Python version is available.
3. **Install dependencies**: Installs the required dependencies (`pytest`, `pytest-testinfra`, Wazuh agent, etc.).
4. **Install Wazuh agent**: Installs and starts the Wazuh agent service.
5. **Run YARA install script**: Executes a script to install YARA.
6. **Run tests**: Executes the `pytest` suite.

## Conclusion

These tests help ensure that the Wazuh agent and YARA are properly installed and configured on the system, which is essential for system security and malware detection. Running these tests regularly through GitHub Actions ensures that every change to the repository is automatically verified.

## See also
- [`install.sh`](../install.sh) for the installation logic these tests verify.
- [`yara.py`](./yara.py) for the test implementation.
