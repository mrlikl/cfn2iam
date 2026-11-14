"""A small Service Authorization Reference and backend for the scoping tests.

The ARN formats are copied from the published servicereference/ files, oddities included.
"""

import json

from cfn2iam import core


def action(name, *resources):
    return {name.lower(): {"name": name, "resources": list(resources)}}


def service(prefix, actions, resources):
    merged = {}
    for a in actions:
        merged.update(a)
    return {
        "service": prefix,
        "actions": merged,
        "resources": {name: {"arnFormats": formats} for name, formats in resources.items()},
    }


S3 = service(
    "s3",
    [
        action("CreateBucket", "bucket"),
        action("DeleteBucket", "bucket"),
        action("GetObject", "accesspointobject", "object"),
        action("ListAllMyBuckets"),
    ],
    {
        "bucket": ["arn:${Partition}:s3:::${BucketName}"],
        "object": ["arn:${Partition}:s3:::${BucketName}/${ObjectName}"],
        "accesspointobject": [
            "arn:${Partition}:s3:${Region}:${Account}:accesspoint/${AccessPointName}/object/${ObjectName}"
        ],
    },
)
IAM = service(
    "iam",
    [action("CreateRole", "role"), action("PassRole", "role"), action("DeleteRole", "role"), action("ListRoles")],
    {"role": ["arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}"]},
)
SQS = service(
    "sqs",
    [action("CreateQueue", "queue"), action("ListQueues")],
    {"queue": ["arn:${Partition}:sqs:${Region}:${Account}:${QueueName}"]},
)
LAMBDA = service(
    "lambda",
    [
        action("CreateFunction", "function"),
        action("DeleteFunction", "function"),
        action("GetLayerVersion", "layerVersion"),
        action("TagResource", "function", "code signing config", "event source mapping"),
    ],
    {
        "function": ["arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}"],
        "code signing config": [
            "arn:${Partition}:lambda:${Region}:${Account}:code-signing-config:${CodeSigningConfigId}"
        ],
        "event source mapping": ["arn:${Partition}:lambda:${Region}:${Account}:event-source-mapping:${UUID}"],
        "layerVersion": ["arn:${Partition}:lambda:${Region}:${Account}:layer:${LayerName}:${LayerVersion}"],
    },
)
EC2_TYPES = {
    "image": ["arn:${Partition}:ec2:${Region}::image/${ImageId}"],
    "instance": ["arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}"],
    "key-pair": ["arn:${Partition}:ec2:${Region}:${Account}:key-pair/${KeyPairName}"],
    "network-interface": ["arn:${Partition}:ec2:${Region}:${Account}:network-interface/${NetworkInterfaceId}"],
    "security-group": ["arn:${Partition}:ec2:${Region}:${Account}:security-group/${SecurityGroupId}"],
    "subnet": ["arn:${Partition}:ec2:${Region}:${Account}:subnet/${SubnetId}"],
    "volume": ["arn:${Partition}:ec2:${Region}:${Account}:volume/${VolumeId}"],
    "license-configuration": [
        "arn:${Partition}:license-manager:${Region}:${Account}:license-configuration:${LicenseConfigurationId}"
    ],
}
EC2 = service("ec2", [action("RunInstances", *EC2_TYPES), action("DescribeInstances")], EC2_TYPES)
DYNAMODB = service(
    "dynamodb",
    [action("CreateTable", "table"), action("CreateTableReplica", "table"), action("DescribeStream", "stream")],
    {
        "table": ["arn:${Partition}:dynamodb:${Region}:${Account}:table/${TableName}"],
        "stream": ["arn:${Partition}:dynamodb:${Region}:${Account}:table/${TableName}/stream/${StreamLabel}"],
    },
)
LOGS = service(
    "logs",
    [action("CreateLogGroup", "log-group"), action("PutLogEvents", "log-stream"), action("DescribeLogGroups")],
    {
        "log-group": ["arn:${Partition}:logs:${Region}:${Account}:log-group:${LogGroupName}"],
        "log-stream": [
            "arn:${Partition}:logs:${Region}:${Account}:log-group:${LogGroupName}:log-stream:${LogStreamName}"
        ],
    },
)
ELASTICFILESYSTEM = service(
    "elasticfilesystem",
    [action("CreateFileSystem", "file-system")],
    {"file-system": ["arn:${Partition}:elasticfilesystem:${Region}:${Account}:file-system/${FileSystemId}"]},
)
BACKUP = service(
    "backup",
    [action("TagResource", "backupVault", "recoveryPoint")],
    {
        "backupVault": ["arn:${Partition}:backup:${Region}:${Account}:backup-vault:${BackupVaultName}"],
        "recoveryPoint": ["arn:${Partition}:${Vendor}:${Region}:*:${ResourceType}:${RecoveryPointId}"],
    },
)

SERVICES = {
    "s3": S3,
    "iam": IAM,
    "sqs": SQS,
    "lambda": LAMBDA,
    "ec2": EC2,
    "dynamodb": DYNAMODB,
    "logs": LOGS,
    "elasticfilesystem": ELASTICFILESYSTEM,
    "backup": BACKUP,
}
REFERENCE = {"servicereference/index.json": {"services": {p: {"filename": f"{p}.json"} for p in SERVICES}}}
REFERENCE.update({f"servicereference/{p}.json": data for p, data in SERVICES.items()})


def schema(allow=(), delete=()):
    handlers = {"create": {"permissions": list(allow)}}
    if delete:
        handlers["delete"] = {"permissions": list(delete)}
    return {"handlers": handlers}


SCHEMAS = {
    "schemas/index.json": {"schemas": []},
    "schemas/AWS_S3_Bucket.json": schema(
        ["s3:CreateBucket", "s3:GetObject", "s3:ListAllMyBuckets"], ["s3:DeleteBucket"]
    ),
    "schemas/AWS_IAM_Role.json": schema(["iam:CreateRole", "iam:PassRole", "iam:ListRoles"], ["iam:DeleteRole"]),
    "schemas/AWS_SQS_Queue.json": schema(["sqs:CreateQueue", "sqs:ListQueues"]),
    "schemas/AWS_Lambda_Function.json": schema(
        ["lambda:CreateFunction", "lambda:GetLayerVersion", "lambda:TagResource", "iam:PassRole"],
        ["lambda:DeleteFunction"],
    ),
    "schemas/AWS_EC2_Instance.json": schema(["ec2:RunInstances", "ec2:DescribeInstances"]),
    "schemas/AWS_DynamoDB_Table.json": schema(["dynamodb:CreateTable", "dynamodb:DescribeStream"]),
    "schemas/AWS_DynamoDB_GlobalTable.json": schema(["dynamodb:CreateTable", "dynamodb:CreateTableReplica"]),
    "schemas/AWS_Logs_LogGroup.json": schema(["logs:CreateLogGroup", "logs:PutLogEvents", "logs:DescribeLogGroups"]),
    "schemas/AWS_SageMaker_Domain.json": schema(["efs:CreateFileSystem", "sagemaker:CreateDomain"]),
    "schemas/AWS_Odd_Thing.json": schema(["s3:*", "ec2:Describe*", "s3:HeadObject", "", "backup:TagResource"]),
}

BACKEND = {**SCHEMAS, **REFERENCE}


def backend(files=None, fail=()):
    """A sync fetch_json over a dict of paths, recording each fetch; paths in ``fail`` raise."""
    files = BACKEND if files is None else files
    fetched = []

    def fetch(path):
        fetched.append(path)
        if path in fail:
            raise OSError("connection refused")
        if path not in files:
            raise core.NotFound(path)
        return json.loads(json.dumps(files[path]))

    fetch.fetched = fetched
    return fetch


def template(*types):
    return json.dumps({"Resources": {f"R{i}": {"Type": t} for i, t in enumerate(types)}})
