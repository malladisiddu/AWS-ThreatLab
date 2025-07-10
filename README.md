# AWS Threat Simulation Framework

A CLI tool to simulate AWS attack scenarios and verify detections via CloudTrail and CloudWatch.

## Prerequisites

- Python 3.9+
- AWS CLI v2
- An AWS account with appropriate IAM permissions

## Installation

```bash
git clone git@github.com:<your-org>/aws-threat-sim.git
cd aws-threat-sim
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### CLI Commands

#### Basic Commands

* **version**
```bash
python cli.py version
```
Prints the current CLI version.

#### IAM Escalation Scenario

* **iam_escalation**
```bash
python cli.py iam_escalation --profile <profile> --region <region>
```
Simulates creating a user and attaching an AdministratorAccess policy.

* **iam_detect**
```bash
python cli.py iam_detect --profile <profile> --region <region>
```
Detects whether an `AttachUserPolicy` event occurred in CloudTrail within the last 15 minutes and generates a JSON report (`report_iam_escalation.json`).

* **iam_cleanup**
```bash
python cli.py iam_cleanup --profile <profile> --region <region>
```
Cleans up the IAM user and policy created during the IAM escalation scenario.

#### S3 Exfiltration Scenario

* **s3_exfil**
```bash
python cli.py s3_exfil --profile <profile> --region <region>
```
Simulates a data exfiltration attack on an S3 bucket by:
  * Creating a temporary bucket
  * Uploading a test object
  * Making it public
  * Reading the object (simulated attacker behavior)

* **s3_detect**
```bash
python cli.py s3_detect --profile <profile> --region <region>
```
Scans CloudTrail for `GetObject` events in the last 15 minutes. Generates a detection report at `report_s3_exfiltration.json`.

* **s3_cleanup**
```bash
python cli.py s3_cleanup --profile <profile> --region <region>
```
Deletes the test S3 bucket and objects created during the scenario.

#### Lambda Backdoor Scenario

* **lambda_backdoor**
```bash
python cli.py lambda_backdoor --profile <profile> --region <region>
```
Deploys a malicious Lambda function with:
  * Excessive IAM permissions (S3, EC2, IAM access)
  * Backdoor functionality for remote command execution
  * Persistence mechanisms

* **lambda_detect**
```bash
python cli.py lambda_detect --profile <profile> --region <region>
```
Detects Lambda backdoor activities via CloudTrail events including function creation, role assignments, and suspicious invocations.

* **lambda_cleanup**
```bash
python cli.py lambda_cleanup --profile <profile> --region <region>
```
Removes the Lambda function, IAM role, and associated policies.

#### EC2 Lateral Movement Scenario

* **ec2_lateral**
```bash
python cli.py ec2_lateral --profile <profile> --region <region>
```
Simulates EC2-based lateral movement by:
  * Launching an EC2 instance with overprivileged IAM role
  * Creating overly permissive security groups
  * Simulating credential harvesting via user data
  * Testing cross-service access

* **ec2_detect**
```bash
python cli.py ec2_detect --profile <profile> --region <region>
```
Detects EC2 lateral movement activities including instance launches with IAM roles, security group modifications, and privilege escalation.

* **ec2_cleanup**
```bash
python cli.py ec2_cleanup --profile <profile> --region <region>
```
Terminates EC2 instances and removes security groups, IAM roles, and policies.

#### Cross-Account Abuse Scenario

* **cross_account**
```bash
python cli.py cross_account --profile <profile> --region <region>
```
Creates a cross-account role with:
  * Overly permissive trust policies (wildcard principals)
  * Excessive permissions for external account access
  * Test role assumption functionality

* **cross_account_detect**
```bash
python cli.py cross_account_detect --profile <profile> --region <region>
```
Detects cross-account abuse via role assumptions, external IP access, and overly permissive trust policies.

* **cross_account_cleanup**
```bash
python cli.py cross_account_cleanup --profile <profile> --region <region>
```
Removes cross-account roles and associated policies.

#### Advanced Detection

* **advanced_detect**
```bash
python cli.py advanced_detect --profile <profile> --region <region>
```
Runs comprehensive threat detection across all scenarios with:
  * Multi-vector attack analysis
  * Threat scoring (0-5 scale)
  * Risk categorization (Low/Medium/High)
  * Detailed event breakdown

#### Cleanup Commands

* **cleanup_all**
```bash
python cli.py cleanup_all --profile <profile> --region <region>
```
Comprehensive cleanup of all scenario artifacts across all attack vectors.
## Report Files
After running `iam_detect`, a report file is generated in the project root:

```bash
report_iam_escalation.json
```
This file contains details on detection status and event records.

## Development

* Scenarios live under `scenarios/`.

* Detection modules live under `detection/`.

* Analyzer modules live under `analyzer/`.

## Contributing

Contributions are welcome! Please open issues or submit pull requests.
