# Exam Tip
In the exam, I noticed that certain keywords may serve as hints to the answer of the question.

For example:
- "PII", "leaked" --> Macie
- "dashboard", "compliance" --> Security Hub
- "audit trail" --> CloudTrail
- "metrics", "monitoring" --> Cloudwatch
- "All accounts must have x restrictions" --> SCP

Therefore, I compiled this list of in-scope AWS services (from Pages 17-18 of the [official exam guide](https://d1.awsstatic.com/training-and-certification/docs-security-spec/AWS-Certified-Security-Specialty_Exam-Guide.pdf)) and the keywords associated with each one.

| AWS Service| Keywords |
|--------------|----------|
| AWS CloudTrail | audit, API activity, audit trail |
| Amazon CloudWatch | metrics, alarms, monitoring, CPU usage, agent |
| AWS Config | compliance, configuration, rules |
| AWS Organizations | consolidated, SCP, organization units |
| AWS Systems Manager | runbooks, automation |
| AWS Trusted Advisor | best practices, optimization, guidance |
| Amazon VPC: Network Access Analyzer | reachability, diagnostics |
| Amazon VPC: Network ACLs | stateless, subnet, allow/deny |
| Amazon VPC: Security groups | stateful, instance, whitelist |
| Amazon VPC: VPC Endpoints | private connection, AWS services |
| AWS Audit Manager | compliance, audit, reports |
| AWS Certificate Manager (ACM) | SSL/TLS certificates, automated renewal |
| AWS CloudHSM | dedicated hardware, encryption keys, government regulations |
| Amazon Detective | investigation, incident response |
| AWS Directory Service | AD, active directory, authentication |
| AWS Firewall Manager | centralized rules, WAF |
| Amazon GuardDuty | threat detection, anomalies, ML |
| AWS IAM Identity Center (SSO) | SSO, user permissions, federation, SAML 2.0 |
| AWS Identity and Access Management (IAM) | permissions, roles, groups, users |
| Amazon Inspector | vulnerability scan, CVE |
| AWS Key Management Service (KMS) | encryption, key management, key rotation, key storage |
| Amazon Macie | sensitive data, PII |
| AWS Network Firewall | packet inspection, traffic control |
| AWS Security Hub | compliance, ASFF findings, dashboard, consolidate, framework |
| AWS Shield | DDoS, cost protection |
| AWS WAF | web exploits, rule-based protection, web application |
