# AWS-ThreatLab

**A comprehensive CLI tool for simulating AWS attack scenarios and validating security detections**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail-orange.svg)](https://aws.amazon.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [AWS Setup Guide](#aws-setup-guide)
- [Installation](#installation)
- [Attack Scenarios](#attack-scenarios)
- [Detection & Reports](#detection--reports)
- [Security Guidelines](#security-guidelines)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Overview

AWS-ThreatLab is designed for defensive security teams to validate their detection capabilities by simulating realistic attack scenarios across AWS services.

### Key Features

- **Attack Simulation**: Five comprehensive attack scenarios covering IAM escalation, S3 exfiltration, Lambda backdoors, EC2 lateral movement, and cross-account abuse
- **Detection Validation**: Real-time threat detection using CloudTrail events with comprehensive reporting
- **Automated Cleanup**: Complete resource cleanup to prevent cost accumulation
- **Enterprise Ready**: JSON reports, error handling, and production-safe design
- **Risk Assessment**: Multi-vector threat analysis with scoring (0-5 scale)

### Use Cases

- Validate security monitoring and detection capabilities
- Test incident response procedures
- Assess security posture across AWS services
- Train security teams on attack patterns
- Compliance validation for security controls

---

## Quick Start

### Prerequisites
- Python 3.9+
- AWS CLI v2
- AWS account with appropriate IAM permissions
- CloudTrail enabled for detection capabilities

### Basic Workflow

```bash
# 1. Clone and setup
git clone https://github.com/malladisiddu/AWS-ThreatLab.git
cd AWS-ThreatLab
pip install -r requirements.txt

# 2. View the CLI banner and available commands
python cli.py

# 3. Run a scenario
python cli.py iam-escalation --profile your-profile --region us-east-1

# 4. Test detection (wait 2-3 minutes for CloudTrail propagation)
python cli.py iam-detect --profile your-profile --region us-east-1

# 5. Clean up resources
python cli.py iam-cleanup --profile your-profile --region us-east-1
```

### CLI Interface

When you run the tool, you'll see a professional banner:

```
╔═════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                     ║
║     █████╗ ██╗    ██╗███████╗    ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗ ║
║    ██╔══██╗██║    ██║██╔════╝    ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝ ║
║    ███████║██║ █╗ ██║███████╗       ██║   ███████║██████╔╝█████╗  ███████║   ██║    ║
║    ██╔══██║██║███╗██║╚════██║       ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║    ║
║    ██║  ██║╚███╔███╔╝███████║       ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║    ║
║    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ║
║                                                                                     ║
║                        ██╗      █████╗ ██████╗                                      ║
║                        ██║     ██╔══██╗██╔══██╗                                     ║
║                        ██║     ███████║██████╔╝                                     ║
║                        ██║     ██╔══██║██╔══██╗                                     ║
║                        ███████╗██║  ██║██████╔╝                                     ║
║                        ╚══════╝╚═╝  ╚═╝╚═════╝                                      ║
║                                                                                     ║
║                             AWS-ThreatLab v1.0                                      ║
║                                                                                     ║
║               Validate Your Security Detections | Test Your Defenses                ║
║                                                                                     ║
║                        Author  - Siddartha Malladi                                  ║
║                        Email   - malladisiddu@gmail.com                             ║
║                        Twitter - st0ic3r                                            ║
║                                                                                     ║
╚═════════════════════════════════════════════════════════════════════════════════════╝
```

---

## AWS Setup Guide

### Step 1: AWS Account Configuration

If you don't have an AWS account:
1. Create an account at [aws.amazon.com](https://aws.amazon.com)
2. Complete email verification and add a payment method
3. **Note**: Use a dedicated testing account, never production

### Step 2: Enable CloudTrail

> **⚠️ WARNING**: CloudTrail is required for threat detection functionality

1. Navigate to **CloudTrail** in AWS Console
2. **Create Trail** with the following settings:
   - Trail name: `threat-simulation-trail`
   - Apply to all regions: **Yes**
   - Management events: **Read and Write**
   - Data events: **S3 and Lambda** (recommended)
3. **Enable the trail**

**Cost Note**: CloudTrail may incur charges. Review pricing at [aws.amazon.com/cloudtrail/pricing](https://aws.amazon.com/cloudtrail/pricing/)

### Step 3: Create IAM User and Permissions

#### Create IAM User
1. **IAM Console** → Users → **Create User**
2. Username: `threat-simulation-user`
3. Access type: **Programmatic access**

#### Create Custom Policy

Create a new policy with the following JSON:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:*",
                "lambda:*",
                "ec2:*",
                "s3:*",
                "cloudtrail:*",
                "logs:*",
                "sts:*",
                "events:*",
                "apigateway:*",
                "secretsmanager:*",
                "rds:Describe*",
                "ssm:*"
            ],
            "Resource": "*"
        }
    ]
}
```

- Policy name: `ThreatSimulationPolicy`
- Attach this policy to the `threat-simulation-user`

#### Download Credentials
- Download the CSV file or copy the Access Key ID and Secret Access Key
- Store credentials securely (you cannot retrieve the secret key again)

### Step 4: Configure AWS CLI

```bash
# Install AWS CLI v2
# macOS: brew install awscli
# Linux/Windows: Download from https://aws.amazon.com/cli/

# Configure credentials
aws configure --profile testing

# When prompted, enter:
# AWS Access Key ID: [Your Access Key]
# AWS Secret Access Key: [Your Secret Key]
# Default region name: us-east-1
# Default output format: json

# Test configuration
aws sts get-caller-identity --profile testing
```

---

## Installation

```bash
# Clone repository
git clone https://github.com/malladisiddu/AWS-ThreatLab.git
cd AWS-ThreatLab

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
python cli.py --help
```

---

## Attack Scenarios

### IAM Privilege Escalation

Simulates unauthorized privilege escalation through IAM policy attachment.

```bash
# Deploy scenario
python cli.py iam-escalation --profile testing --region us-east-1

# Detect threats
python cli.py iam-detect --profile testing --region us-east-1

# Clean up
python cli.py iam-cleanup --profile testing --region us-east-1
```

**Scenario Details:**
- Creates test IAM user
- Attaches `AdministratorAccess` policy
- Simulates privilege escalation attack patterns

### S3 Data Exfiltration

Simulates data theft through S3 bucket manipulation and unauthorized access.

```bash
# Deploy scenario
python cli.py s3-exfil --profile testing --region us-east-1

# Detect threats
python cli.py s3-detect --profile testing --region us-east-1

# Clean up
python cli.py s3-cleanup --profile testing --region us-east-1
```

**Scenario Details:**
- Creates temporary S3 bucket with test data
- Attempts to make bucket publicly accessible
- Simulates data exfiltration patterns

### Lambda Backdoor

Deploys malicious serverless functions with persistence mechanisms.

```bash
# Deploy scenario
python cli.py lambda-backdoor --profile testing --region us-east-1

# Detect threats
python cli.py lambda-detect --profile testing --region us-east-1

# Clean up
python cli.py lambda-cleanup --profile testing --region us-east-1
```

**Scenario Details:**
- Creates Lambda function with excessive permissions
- Implements backdoor functionality simulation
- Tests serverless persistence mechanisms

### EC2 Lateral Movement

Simulates credential harvesting and lateral movement through EC2 instances.

```bash
# Deploy scenario
python cli.py ec2-lateral --profile testing --region us-east-1

# Detect threats
python cli.py ec2-detect --profile testing --region us-east-1

# Clean up
python cli.py ec2-cleanup --profile testing --region us-east-1
```

**Scenario Details:**
- Launches EC2 instance with overprivileged IAM role
- Creates overly permissive security groups
- Simulates credential harvesting via user data scripts

### Cross-Account Abuse

Tests cross-account trust relationship vulnerabilities.

```bash
# Deploy scenario
python cli.py cross-account --profile testing --region us-east-1

# Detect threats
python cli.py cross-account-detect --profile testing --region us-east-1

# Clean up
python cli.py cross-account-cleanup --profile testing --region us-east-1
```

**Scenario Details:**
- Creates IAM role with overly permissive trust policy
- Tests external account access capabilities
- Simulates cross-account privilege escalation

### Advanced Threat Detection

Comprehensive analysis across all attack vectors with threat scoring.

```bash
# Run complete threat analysis
python cli.py advanced-detect --profile testing --region us-east-1
```

**Sample Output:**
```
Advanced Threat Detection Results:
Threat Score: 2/5
Total Events: 7
MEDIUM RISK: Some suspicious activities detected

Detection Breakdown:
  lambda_backdoor: NOT DETECTED (0 events)
  ec2_lateral_movement: DETECTED (3 events)
  cross_account_abuse: NOT DETECTED (0 events)
  iam_escalation: DETECTED (4 events)
  s3_exfiltration: NOT DETECTED (0 events)
```

---

## Detection & Reports

### Report Generation

All detection commands generate detailed JSON reports for analysis:

| Report File | Description |
|-------------|-------------|
| `report_iam_escalation.json` | IAM privilege escalation detection results |
| `report_s3_exfiltration.json` | S3 data exfiltration analysis |
| `report_lambda_backdoor.json` | Lambda backdoor detection results |
| `report_ec2_lateral_movement.json` | EC2 lateral movement analysis |
| `report_cross_account_abuse.json` | Cross-account abuse detection |
| `report_advanced_threat_detection.json` | Comprehensive threat analysis |

### Sample Report Structure

#### IAM Escalation Detection Report
```json
{
  "scenario": "iam_escalation",
  "detected": true,
  "event_count": 1,
  "timestamp": "2024-01-15T10:30:45.123456",
  "events": [
    {
      "EventId": "12345678-1234-1234-1234-123456789012",
      "EventName": "AttachUserPolicy",
      "EventTime": "2024-01-15T10:25:22+00:00",
      "EventSource": "iam.amazonaws.com",
      "Username": "threat-simulation-user",
      "Resources": [
        {
          "ResourceType": "AWS::IAM::User",
          "ResourceName": "poctest-user"
        },
        {
          "ResourceType": "AWS::IAM::Policy",
          "ResourceName": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
      ],
      "SourceIPAddress": "203.0.113.12",
      "UserAgent": "Boto3/1.39.4 Botocore/1.39.4"
    }
  ]
}
```

#### Advanced Threat Detection Report
```json
{
  "scenario": "advanced_threat_detection",
  "detected": true,
  "event_count": 8,
  "timestamp": "2024-01-15T10:35:12.654321",
  "events": {
    "threat_score": 3,
    "total_events": 8,
    "high_risk": true,
    "medium_risk": false,
    "low_risk": false,
    "detections": {
      "lambda_backdoor": {
        "detected": true,
        "event_count": 2,
        "events": [...]
      },
      "ec2_lateral_movement": {
        "detected": true,
        "event_count": 4,
        "events": [...]
      },
      "cross_account_abuse": {
        "detected": false,
        "event_count": 0,
        "events": []
      },
      "iam_escalation": {
        "detected": true,
        "event_count": 2,
        "events": [...]
      },
      "s3_exfiltration": {
        "detected": false,
        "event_count": 0,
        "events": []
      }
    }
  }
}
```

### Risk Assessment Scoring

| Threat Score | Risk Level | Description |
|-------------|------------|-------------|
| 0 | LOW | No immediate threats detected |
| 1-2 | MEDIUM | Some suspicious activities detected |
| 3+ | HIGH | Multiple attack vectors detected |

---

## Security Guidelines

### Critical Security Requirements

> **⚠️ WARNING**: This framework requires broad AWS permissions for testing purposes. Use only in dedicated testing accounts.

#### Account Isolation
- **Never use production AWS accounts** for threat simulation
- Use dedicated security testing accounts with proper boundaries
- Implement monitoring and alerting for all testing activities
- Consider using AWS Organizations for account separation

#### Credential Management
- Use AWS CLI profiles instead of hardcoded credentials
- Enable MFA on your AWS account root user
- Rotate access keys regularly
- Consider using AWS STS for temporary credentials

#### Cost Management
- Set up billing alerts before conducting tests
- Always run cleanup commands after scenario completion
- Monitor AWS costs using Cost Explorer
- Use the `cleanup-all` command for comprehensive resource removal

#### Legal and Compliance
- Ensure proper authorization before conducting security tests
- Document all testing activities for audit purposes
- Follow organizational security policies and procedures
- Consider regulatory requirements (SOC2, PCI-DSS, etc.)

### Recommended Account Architecture

```
Production Account (123456789012)
├── No threat simulation tools
└── Strict access controls and monitoring

Security Testing Account (987654321098)
├── Threat simulation framework deployment
├── CloudTrail enabled with comprehensive logging
├── Real-time monitoring and alerting
└── Complete isolation from production systems
```

---

## Troubleshooting

### Common Issues

#### Credential Errors
**Error**: "NoCredentialsError" or "Unable to locate credentials"

**Solution**:
```bash
# Check AWS CLI configuration
aws configure list --profile testing

# Verify credentials functionality
aws sts get-caller-identity --profile testing

# List available profiles
aws configure list-profiles
```

#### Access Denied Errors
**Error**: "An error occurred (AccessDenied)"

**Solutions**:
- Verify IAM user has `ThreatSimulationPolicy` attached
- Confirm policy JSON formatting is correct
- Ensure you're using the correct AWS region
- Verify CloudTrail is enabled and accessible

#### Detection Issues
**Error**: "No events found" during detection

**Solutions**:
- Wait 5-15 minutes for CloudTrail event propagation
- Verify CloudTrail is enabled and actively logging
- Confirm CloudTrail is capturing the correct event types
- Ensure scenario and detection commands use the same region

#### EC2 Launch Failures
**Error**: EC2 instance launch failures

**Solutions**:
- Verify your account has a default VPC and subnets
- Check EC2 service limits in your target region
- Ensure t2.micro instances are available in your region
- Try switching to us-east-1 or us-west-2

#### Cost Management
**Issue**: Unexpected AWS charges

**Solutions**:
```bash
# Run comprehensive cleanup
python cli.py cleanup-all --profile testing --region us-east-1

# Check for remaining resources
aws ec2 describe-instances --profile testing
aws lambda list-functions --profile testing
aws s3 ls --profile testing
```

### Debug Commands

```bash
# Test basic functionality
python cli.py version

# Verify AWS connectivity
aws sts get-caller-identity --profile testing

# Validate Python imports
python -c "from scenarios.iam_escalation import run, cleanup"

# Check CloudTrail configuration
aws cloudtrail describe-trails --profile testing
```

---

## Contributing

### Development Environment Setup

```bash
# Clone repository
git clone https://github.com/malladisiddu/AWS-ThreatLab.git
cd AWS-ThreatLab

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Validate installation
python -m py_compile scenarios/*.py detection/*.py
python cli.py --help
```

### Project Structure

```
aws-threatlab/
├── scenarios/              # Attack scenario implementations
│   ├── iam_escalation.py
│   ├── s3_exfiltration.py
│   ├── lambda_backdoor.py
│   ├── ec2_lateral_movement.py
│   └── cross_account_abuse.py
├── detection/              # Detection logic and CloudTrail analysis
│   └── cloudtrail.py
├── analyzer/               # Report generation and analysis
│   └── report.py
├── cli.py                  # Main CLI interface
├── requirements.txt        # Python dependencies
└── README.md              # Project documentation
```

### Adding New Scenarios

1. Create new scenario file in `scenarios/` directory
2. Implement `run()` and `cleanup()` functions following existing patterns
3. Add corresponding detection logic to `detection/cloudtrail.py`
4. Update CLI commands in `cli.py`
5. Test thoroughly in isolated environment
6. Update documentation and examples

### Development Guidelines

- Focus on defensive security capabilities and detection validation
- Follow secure coding practices and input validation
- Ensure comprehensive error handling and logging
- Maintain backwards compatibility for CLI interface
- Test all changes in isolated AWS environments

### Code Review Requirements

- All scenarios must include proper cleanup functionality
- Detection logic must be thoroughly tested
- New features require documentation updates
- Security implications must be clearly documented

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

**Disclaimer**: This tool is designed for defensive security testing purposes only. Users are responsible for ensuring proper authorization and compliance with all applicable laws and regulations.

---

**Built for Security Teams | Validate Your Defenses | Improve Your Posture**

[Report Issues](https://github.com/malladisiddu/AWS-ThreatLab/issues) • [Documentation](https://github.com/malladisiddu/AWS-ThreatLab/wiki) • [Discussions](https://github.com/malladisiddu/AWS-ThreatLab/discussions)