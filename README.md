# AWS IAM Policy Verification Tool

## Overview
This tool is designed for the validation of AWS IAM Role Policy JSON strings. It specifically checks for overly permissive policy settings by ensuring that the 'Resource' field does not contain a single asterisk (`*`). This is crucial for maintaining security best practices by preventing the unintentional granting of wide-ranging permissions.

## Function Description
The `checkIAMPolicy` function takes a JSON string as input and returns a boolean value. It performs three key checks:

1. Verifies the input string is in valid JSON format.
2. Ensures required fields (`PolicyDocument` and `PolicyName`) are present in the policy document.
3. Checks the policy does not grant unrestricted access, particularly looking for the presence of an asterisk (`*`) in the 'Resource' field, which indicates overly broad permissions.

## How to Run the Unit Tests

### Preparing Your Environment
- Ensure Python 3.6 or higher is installed on your system.
- The `unittest` framework, included with Python, will be used to run the tests.

### Running the Tests
1. Place the `checkIAMPolicy` function code in a file named `policy_checker.py`.
2. Place the unit tests for `checkIAMPolicy` in a file named `test_policy_checker.py`.
3. Save both files in a working directory of your choice.
4. Open a terminal or command prompt.
5. Navigate to the directory containing both files.
6. Run the tests by executing the command: `python -m unittest test_policy_checker.py`.
