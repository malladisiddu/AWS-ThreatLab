# AWS Threat Simulation Framework

A CLI tool to simulate AWS attack scenarios and verify detections via CloudTrail and CloudWatch.

## Prerequisites

- Python 3.9+
- AWS CLI v2
- An AWS account with appropriate IAM permissions

## AWS Account Setup

### 1. Create AWS Account

If you don't have an AWS account:
1. Go to [https://aws.amazon.com](https://aws.amazon.com)
2. Click "Create an AWS Account"
3. Follow the registration process
4. Verify your email and phone number
5. Add a payment method (required even for free tier)

### 2. Enable CloudTrail (Required for Detection)

CloudTrail is essential for this framework to detect attack scenarios:

1. **Sign in to AWS Console**
2. **Navigate to CloudTrail service**
3. **Create a trail** (if not already exists):
   - Trail name: `threat-simulation-trail`
   - Apply trail to all regions: `Yes`
   - Read/Write events: `All`
   - Data events: `S3` and `Lambda` (recommended)
   - Storage location: Create new S3 bucket or use existing
4. **Enable the trail**

> **Important**: CloudTrail may incur charges for data events and storage. Review pricing at https://aws.amazon.com/cloudtrail/pricing/

### 3. Create IAM User for Threat Simulation

**⚠️ Security Note**: This framework requires broad permissions for testing purposes. Use a dedicated testing account, not production.

#### Step 3.1: Create IAM User
1. **Go to IAM Console** → Users → Add User
2. **User name**: `threat-simulation-user`
3. **Access type**: Programmatic access (Access Key ID and Secret)
4. **Click Next: Permissions**

#### Step 3.2: Create Custom Policy
1. **Click "Create policy"**
2. **Switch to JSON tab**
3. **Paste the following policy**:

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

4. **Name**: `ThreatSimulationPolicy`
5. **Description**: `Policy for AWS Threat Simulation Framework`
6. **Click Create Policy**

#### Step 3.3: Attach Policy to User
1. **Go back to user creation**
2. **Click "Attach existing policies directly"**
3. **Search for**: `ThreatSimulationPolicy`
4. **Select the policy** and click Next
5. **Add tags** (optional):
   - Key: `Purpose`, Value: `ThreatSimulation`
   - Key: `Environment`, Value: `Testing`
6. **Click Create User**

#### Step 3.4: Download Credentials
1. **Download CSV** or copy Access Key ID and Secret Access Key
2. **Store securely** - you won't be able to retrieve the secret key again

### 4. Install and Configure AWS CLI

#### Step 4.1: Install AWS CLI v2

**macOS (Homebrew)**:
```bash
brew install awscli
```

**macOS (Direct)**:
```bash
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
```

**Linux**:
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Windows**:
Download and run: https://awscli.amazonaws.com/AWSCLIV2.msi

#### Step 4.2: Configure AWS CLI

```bash
aws configure
```

Enter the following when prompted:
- **AWS Access Key ID**: `[Your Access Key from Step 3.4]`
- **AWS Secret Access Key**: `[Your Secret Key from Step 3.4]`
- **Default region name**: `us-east-1` (or your preferred region)
- **Default output format**: `json`

#### Step 4.3: Test AWS CLI Configuration

```bash
aws sts get-caller-identity
```

Expected output:
```json
{
    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/threat-simulation-user"
}
```

### 5. Configure AWS Profiles (Optional but Recommended)

For better security, you can create separate profiles:

```bash
# Configure testing profile
aws configure --profile testing
```

Then use the framework with:
```bash
python cli.py iam-escalation --profile testing --region us-east-1
```

## Installation

```bash
git clone https://github.com/malladisiddu/AWS-Threat-Simulation-Framework.git
cd AWS-Threat-Simulation-Framework
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
## Security Best Practices

### 🔒 **Critical Security Guidelines**

1. **Never Use Production Accounts**
   - Always use dedicated testing/sandbox AWS accounts
   - Never run this framework in production environments
   - Set up account boundaries and monitoring

2. **Credential Management**
   - Use AWS CLI profiles instead of hardcoded credentials
   - Rotate access keys regularly
   - Enable MFA on your AWS account
   - Use temporary credentials when possible

3. **Network Security**
   - Run scenarios in isolated VPCs
   - Use security groups to limit access
   - Monitor network traffic during tests

4. **Cost Management**
   - Set up billing alerts
   - Use AWS Cost Explorer to monitor spending
   - Clean up resources immediately after testing
   - Consider using AWS Cost Anomaly Detection

5. **Compliance & Legal**
   - Ensure you have authorization to run security tests
   - Document all testing activities
   - Follow your organization's security policies
   - Consider regulatory requirements (SOC2, PCI-DSS, etc.)

### 🛡️ **Recommended AWS Account Structure**

```
Production Account (123456789012)
├── No threat simulation tools
└── Strict access controls

Security Testing Account (987654321098)  
├── Threat simulation framework
├── CloudTrail enabled
├── Monitoring and alerting
└── Isolated from production
```

## Quick Start Example

After setup, try this basic workflow:

```bash
# 1. Test basic functionality
python cli.py version

# 2. Run a simple scenario
python cli.py iam-escalation --profile testing --region us-east-1

# 3. Wait 1-2 minutes for CloudTrail propagation

# 4. Test detection
python cli.py iam-detect --profile testing --region us-east-1

# 5. Clean up
python cli.py iam-cleanup --profile testing --region us-east-1
```

## Report Files

Reports are generated in JSON format in the project root:

- `report_iam_escalation.json` - IAM privilege escalation detection
- `report_s3_exfiltration.json` - S3 data exfiltration detection  
- `report_lambda_backdoor.json` - Lambda backdoor detection
- `report_ec2_lateral_movement.json` - EC2 lateral movement detection
- `report_cross_account_abuse.json` - Cross-account abuse detection
- `report_advanced_threat_detection.json` - Comprehensive threat analysis

Each report contains:
- Detection status (found/not found)
- Event details from CloudTrail
- Timestamps and source information
- Risk assessment and recommendations

## Troubleshooting

### Common Issues

**1. "NoCredentialsError" or "Unable to locate credentials"**
```bash
# Check AWS CLI configuration
aws configure list

# Verify credentials work
aws sts get-caller-identity

# Check if profile exists
aws configure list-profiles
```

**2. "An error occurred (AccessDenied)"**
- Verify IAM user has the ThreatSimulationPolicy attached
- Check the policy JSON is correctly formatted
- Ensure you're using the correct AWS region

**3. "No events found" during detection**
- Wait 5-15 minutes for CloudTrail propagation
- Verify CloudTrail is enabled and logging
- Check CloudTrail is logging the correct event types
- Ensure events are in the same region

**4. "InvalidAMIID.NotFound" for EC2 scenarios**
- The framework auto-detects AMI IDs, but may fail in some regions
- Try switching to us-east-1 or us-west-2
- Check if your account has default VPC

**5. EC2 instance launch failures**
- Verify your account has default VPC and subnets
- Check EC2 service limits in your region
- Ensure t2.micro instances are available

**6. High AWS costs**
```bash
# Always clean up after testing
python cli.py cleanup-all --profile testing --region us-east-1

# Check what resources are still running
aws ec2 describe-instances --profile testing --region us-east-1
aws lambda list-functions --profile testing --region us-east-1
aws s3 ls --profile testing --region us-east-1
```

### Debug Mode

For detailed debugging, you can:

1. **Enable CloudTrail Data Events** for more detailed logging
2. **Use CloudWatch Logs** to monitor Lambda function execution
3. **Check IAM Access Analyzer** for policy recommendations
4. **Enable AWS Config** for resource compliance monitoring

### Getting Help

- **GitHub Issues**: Report bugs or request features
- **AWS Documentation**: https://docs.aws.amazon.com/
- **CloudTrail Events Reference**: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html

## Development

### Project Structure
```
aws-threat-simulation-framework/
├── scenarios/          # Attack scenario implementations
│   ├── iam_escalation.py
│   ├── s3_exfiltration.py
│   ├── lambda_backdoor.py
│   ├── ec2_lateral_movement.py
│   └── cross_account_abuse.py
├── detection/          # Detection logic
│   └── cloudtrail.py
├── analyzer/           # Report generation
│   └── report.py
├── cli.py             # Main CLI interface
├── requirements.txt   # Python dependencies
└── README.md         # This file
```

### Adding New Scenarios

1. Create scenario file in `scenarios/` directory
2. Implement `run()` and `cleanup()` functions
3. Add detection logic to `detection/cloudtrail.py`
4. Add CLI commands to `cli.py`
5. Update README with new scenario documentation

### Testing

```bash
# Run syntax checks
python -m py_compile scenarios/*.py detection/*.py

# Test imports
python -c "from scenarios.iam_escalation import run, cleanup"

# Test CLI commands
python cli.py --help
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with detailed description
5. Follow security best practices in your code

### Code of Conduct

This project is for **defensive security purposes only**. Contributors must:
- Focus on improving detection capabilities
- Never create malicious tools or exploits
- Follow responsible disclosure for any vulnerabilities found
- Respect AWS terms of service and legal requirements
