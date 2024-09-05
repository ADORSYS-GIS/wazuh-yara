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
pytest -vv
```

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

#### 4. **`test_ossec_conf_content`**
   - **Description**: Validates that the `ossec.conf` contains the expected directories and settings.
   - **Reason**: Ensures the configuration file is properly set up to monitor important directories (`/home`, `/root`, `/bin`, `/sbin`) and that the correct scan frequency is applied.

#### 5. **`test_yara_installed`**
   - **Description**: Verifies that the YARA package is installed.
   - **Reason**: YARA is necessary for malware detection, and this test ensures it's present on the system.

#### 6. **`test_yara_script_downloaded`**
   - **Description**: Ensures the YARA active-response script is downloaded and has the correct permissions.
   - **Reason**: This script is essential for active malware response, so its presence and permissions are crucial.

#### 7. **`test_wazuh_agent_restarted`**
   - **Description**: Checks if the Wazuh agent service is running and enabled.
   - **Reason**: The Wazuh agent must be actively running to monitor the system.

#### 8. **`test_yara_rules_file_exists`**
   - **Description**: Confirms that the YARA rules file exists.
   - **Reason**: YARA rules are essential for detecting malware, so this file must exist.

#### 9. **`test_yara_rules_directory_permissions`**
   - **Description**: Ensures that the YARA rules directory has the correct owner and group permissions (`root` and `wazuh`).
   - **Reason**: Proper permissions are necessary to ensure the integrity of the rules and system security.

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