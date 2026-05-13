---
title: "Local S3 Gateway authentication for non-secure clusters"
date: "2026-05-13"
summary: S3 Gateway-only access-key authentication for non-secure Ozone clusters.
weight: 6
menu:
   main:
      parent: Security
icon: cloud
---
<!---
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

Local S3 Gateway authentication is an experimental feature for non-secure
Ozone clusters. It lets S3 Gateway validate AWS Signature Version 4 requests
against a local credentials file and apply allow rules for S3 bucket and object
actions.

This feature is disabled by default. It is intended for internal Kubernetes,
POC, and restricted deployments where Kerberos daemon login is not practical.
It is not full Ozone cluster security and is not a replacement for
`ozone.security.enabled=true`.

## Security boundary

The security boundary is the S3 Gateway process only. OM, SCM, and Datanodes
remain non-secure when `ozone.security.enabled=false`; direct access through
OM RPC, SCM, Datanode ports, OFS, O3FS, or other native Ozone paths is not
authorized by this feature.

You must block direct client access to OM, SCM, Datanode, and OFS endpoints
with Kubernetes NetworkPolicy, firewall rules, or equivalent controls. Clients
that can bypass S3 Gateway bypass these checks.

If `ozone.security.enabled=true` and local S3 Gateway authentication is also
enabled, S3 Gateway fails startup to avoid ambiguity with the Kerberos-backed
S3 credential flow.

Presigned URLs are not supported by local S3 Gateway authentication. Use normal
SigV4 `Authorization` headers.

## Configuration

Add the following to the S3 Gateway `ozone-site.xml`:

```xml
<property>
  <name>ozone.security.enabled</name>
  <value>false</value>
</property>
<property>
  <name>ozone.s3g.local.auth.enabled</name>
  <value>true</value>
</property>
<property>
  <name>ozone.s3g.local.auth.credentials.file</name>
  <value>/etc/ozone/s3g-credentials.json</value>
</property>
<property>
  <name>ozone.s3g.local.auth.reload.interval</name>
  <value>60s</value>
</property>
<property>
  <name>ozone.s3g.local.auth.fail.on.invalid.config</name>
  <value>true</value>
</property>
<property>
  <name>ozone.s3g.local.auth.compatibility.mode</name>
  <value>strict</value>
</property>
```

`strict` mode requires valid SigV4 on all S3 requests. `permissive` mode keeps
the existing non-secure behavior and is intended only for debugging.

## Credentials file

The credentials file is JSON. `accessKey` values must be unique. `secretKey`
values are used only for signature validation and are not logged.
An optional `principal` field can be set per user; if omitted, S3 Gateway uses
the `accessKey` as the local S3 principal name.

```json
{
  "version": 1,
  "users": [
    {
      "accessKey": "taiga",
      "secretKey": "REPLACE_WITH_SECRET",
      "displayName": "taiga service user",
      "enabled": true,
      "allow": [
        {
          "bucket": "taiga-files",
          "prefix": "*",
          "actions": [
            "ListBucket",
            "HeadBucket",
            "GetObject",
            "PutObject",
            "DeleteObject",
            "CreateMultipartUpload",
            "UploadPart",
            "AbortMultipartUpload",
            "ListMultipartUploadParts",
            "CompleteMultipartUpload"
          ]
        }
      ]
    }
  ]
}
```

Default effect is deny. Disabled users are treated as unknown users. Unknown
access keys, invalid signatures, missing authorization headers, unknown
actions, and unmatched bucket or prefix rules are denied.

For `GET Service` / `ListBuckets`, add an explicit rule with bucket `"*"` and
action `"ListAllMyBuckets"`, or set
`ozone.s3g.local.auth.allow.list.all.buckets=true` to allow authenticated
local S3 users to list all buckets.

## AWS CLI

```bash
aws configure set aws_access_key_id taiga
aws configure set aws_secret_access_key REPLACE_WITH_SECRET
aws configure set default.s3.signature_version s3v4

aws --endpoint-url http://s3g.example.com:9878 s3 ls s3://taiga-files/
aws --endpoint-url http://s3g.example.com:9878 s3 cp ./file.txt s3://taiga-files/file.txt
```

## Kubernetes example

Mount the credentials JSON only into S3 Gateway pods. Do not mount it into OM,
SCM, or Datanode pods.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-selected-clients-to-s3g
  namespace: ozone
spec:
  podSelector:
    matchLabels:
      app: ozone-s3g
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              s3-access: "true"
      ports:
        - protocol: TCP
          port: 9878
```

Use additional NetworkPolicies or firewalls to deny client traffic to OM, SCM,
Datanode, and other native Ozone service ports.

## Design note

This mode exists to provide S3-only authentication and coarse bucket/action
authorization at the stateless S3 Gateway for restricted non-secure clusters.
The backend daemons still run as a non-secure Ozone cluster, and native Ozone
ACLs are not enforced by this feature.

The secure Kerberos S3 flow is unchanged. In secure clusters, users should
continue to obtain S3 secrets with `ozone s3 getsecret` after Kerberos
authentication and use `ozone.security.enabled=true` for full Ozone security.
