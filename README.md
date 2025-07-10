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

* version

```bash
python cli.py version
```
Prints the current CLI version.

* iam_escalation

```bash
python cli.py iam_escalation --profile <profile> --region <region>
```
Simulates creating a user and attaching an AdministratorAccess policy.

* iam_detect

```bash
python cli.py iam_detect --profile <profile> --region <region>
```
Detects whether an `AttachUserPolicy` event occurred in CloudTrail within the last 15 minutes and generates a JSON report (`report_iam_escalation.json`).

* iam_cleanup

```bash
python cli.py iam_cleanup --profile <profile> --region <region>
```
Cleans up the IAM user and policy created during the IAM escalation scenario.

* s3_exfil
```bash
python cli.py s3_exfil --profile <profile> --region <region>
```
Simulates a data exfiltration attack on an S3 bucket by:

    * Creating a temporary bucket.

    * Uploading a test object.

    * Making it public.

    *Reading the object (simulated attacker behavior).
* s3_detect
```bash
python cli.py s3_detect --profile <profile> --region <region>
```
Scans CloudTrail for `GetObject` events in the last 15 minutes. Generates a detection report at `report_s3_exfiltration.json`.
* s3_cleanup
```bash
python cli.py s3_cleanup --profile <profile> --region <region>
```
Deletes the test S3 bucket and objects created during the scenario.
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
