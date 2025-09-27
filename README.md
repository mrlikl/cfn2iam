# CloudFormation to IAM (cfn2iam)
A tool to automatically generate minimal IAM policy to deploy a CloudFormation stack from its template.

Live tool here - https://mrlikl.github.io/cfn2iam/

PyPI - https://pypi.org/project/cfn2iam/

## Overview

This tool analyzes CloudFormation templates to identify all resource types used, then queries the ~~CloudFormation registry~~ GitHub static website ((https://mrlikl.github.io/cfn2iam/backend/schemas/)) to determine the required IAM permissions for each resource type. It can generate IAM policy documents or create IAM roles with the appropriate permissions.

## Features

- (NEW) Added support for [SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)
- Parse CloudFormation templates in JSON or YAML format
- Extract resource types and determine required permissions
- Generate IAM policy documents with appropriate permissions
- Create IAM roles with the generated permissions
- Option to allow or deny delete permissions
- Support for permissions boundaries

## Installation

```bash
pip install cfn2iam
```

For IAM role creation functionality:
```bash
pip install cfn2iam[iam]
```

## Usage

```bash
cfn2iam <template_path> [options]
```

### Options

- `-d, --allow-delete`: Allow delete permissions instead of denying them (default: False)
- `-c, --create-role`: Create an IAM role with the generated permissions (default: False)
- `-r, --role-name`: Name for the IAM role (if not specified, uses 'cfn2iam-<random_hash>')
- `-p, --permissions-boundary`: ARN of the permissions boundary to attach to the role

### Examples

Generate a policy document from a template:
```bash
cfn2iam path/to/template.yaml
```

Create an IAM role with delete permissions allowed:
```bash
cfn2iam path/to/template.yaml -d
```

Create an IAM role with a custom name:
```bash
cfn2iam path/to/template.yaml -r MyCustomRole
```

Create an IAM role with a permissions boundary:
```bash
cfn2iam path/to/template.yaml -p arn:aws:iam::123456789012:policy/boundary
```

## How It Works

1. The tool parses the CloudFormation template to extract all resource types
2. For each resource type, it fetches the schema from pre-hosted GitHub schemas (https://mrlikl.github.io/cfn2iam/backend/schemas/)
3. It categorizes permissions into "update" (create/update/read) and "delete-specific" permissions
4. It generates a policy document with appropriate Allow and Deny statements
5. It saves the policy document to a file with a unique name
6. If requested (default), it creates an IAM role with the generated policy

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
