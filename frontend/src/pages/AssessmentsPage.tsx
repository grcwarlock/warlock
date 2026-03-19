import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Play, CheckCircle, AlertTriangle, XCircle,
  ChevronRight, FileText, Loader2, X,
  Info, BookOpen, Terminal, Copy
} from 'lucide-react';
import api from '../lib/api';

interface AssessmentRun {
  id: string;
  framework: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  total_checks: number;
  passed: number;
  failed: number;
  errors: number;
  pass_rate: number | null;
}

interface AssessmentResult {
  id: string;
  control_id: string;
  check_id: string;
  assertion: string;
  status: string;
  severity: string;
  provider: string;
  region: string;
  findings: string[];
  remediation: string | null;
  assessed_at: string;
}

const FRAMEWORK_LABELS: Record<string, string> = {
  nist_800_53: 'NIST 800-53',
  soc2: 'SOC 2',
  iso_27001: 'ISO 27001',
  hipaa: 'HIPAA',
  cmmc_l2: 'CMMC L2',
};

interface RemediationData {
  steps: string[];
  cli: string[];
}

// ---------------------------------------------------------------------------
// Provider-specific CLI command banks keyed by control family
// ---------------------------------------------------------------------------
const CLI_COMMANDS: Record<string, Record<string, string[]>> = {
  /* ── NIST 800-53 families ─────────────────────────────────────────────── */
  AC: {
    aws: [
      'aws iam list-users --output table',
      'aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d',
      'aws iam list-mfa-devices --user-name <USER>',
      'aws iam update-login-profile --user-name <USER> --password-reset-required',
      'aws iam put-user-policy --user-name <USER> --policy-name DenyWithoutMFA --policy-document file://deny-no-mfa.json',
    ],
    gcp: [
      'gcloud iam service-accounts list --format="table(email,disabled)"',
      'gcloud projects get-iam-policy <PROJECT_ID> --format=json | jq \'.bindings[] | select(.role | contains("admin"))\'',
      'gcloud identity groups memberships list --group-email=<GROUP>',
      'gcloud resource-manager org-policies describe constraints/iam.allowedPolicyMemberDomains --organization=<ORG_ID>',
      'gcloud auth application-default revoke  # rotate stale credentials',
    ],
    azure: [
      'az ad user list --query "[?accountEnabled==true]" -o table',
      'az ad user list --query "[?signInActivity.lastSignInDateTime < \'2025-01-01\']" -o table',
      'az role assignment list --all --query "[?roleDefinitionName==\'Owner\']" -o table',
      'az ad user update --id <USER_ID> --force-change-password-next-sign-in true',
      'az policy assignment create --name enforce-mfa --policy /providers/Microsoft.Authorization/policyDefinitions/<MFA_POLICY_ID>',
    ],
  },
  AT: {
    aws: [
      'aws cognito-idp admin-list-groups-for-user --user-pool-id <POOL> --username <USER>',
      'aws iam get-account-authorization-details --filter User --output json | jq ".UserDetailList[].AttachedManagedPolicies"',
    ],
    gcp: [
      'gcloud iam roles list --project=<PROJECT_ID> --format="table(name,title)"',
    ],
    azure: [
      'az ad user list --filter "department eq \'Security\'" -o table',
    ],
  },
  AU: {
    aws: [
      'aws cloudtrail describe-trails --output table',
      'aws cloudtrail get-trail-status --name <TRAIL_NAME>',
      'aws logs describe-log-groups --query "logGroups[*].[logGroupName,retentionInDays]" --output table',
      'aws logs put-retention-policy --log-group-name <GROUP> --retention-in-days 365',
      'aws cloudwatch put-metric-alarm --alarm-name UnauthorizedAPICalls --metric-name UnauthorizedAttemptCount --namespace CloudTrailMetrics --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <SNS_ARN>',
    ],
    gcp: [
      'gcloud logging sinks list --format="table(name,destination,filter)"',
      'gcloud logging sinks create audit-sink storage.googleapis.com/<BUCKET> --log-filter="logName:cloudaudit.googleapis.com"',
      'gcloud logging read "logName:cloudaudit.googleapis.com/activity" --limit=50 --format=json',
      'gcloud projects get-iam-policy <PROJECT> --format=json | jq \'.auditConfigs\'',
      'gcloud organizations get-iam-policy <ORG_ID> --format=json | jq ".auditConfigs"',
    ],
    azure: [
      'az monitor diagnostic-settings list --resource <RESOURCE_ID> -o table',
      'az monitor diagnostic-settings create --resource <RESOURCE_ID> -n audit-logs --logs \'[{"category":"AuditEvent","enabled":true,"retentionPolicy":{"enabled":true,"days":365}}]\'',
      'az monitor activity-log list --start-time $(date -u -d "-7 days" +%Y-%m-%dT%H:%M:%SZ) --query "[?authorization.action==\'Microsoft.Authorization/roleAssignments/write\']" -o table',
      'az monitor log-analytics workspace list -o table',
      'az security alert list --query "[?status==\'Active\']" -o table',
    ],
  },
  CA: {
    aws: [
      'aws securityhub get-findings --filters \'{"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}]}\' --max-items 25',
      'aws inspector2 list-findings --filter-criteria \'{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}\' --max-results 25',
      'aws auditmanager get-assessment --assessment-id <ID>',
    ],
    gcp: [
      'gcloud scc findings list <ORG_ID> --source=<SOURCE_ID> --filter="state=ACTIVE" --format=json',
      'gcloud scc sources list <ORG_ID> --format="table(name,displayName)"',
    ],
    azure: [
      'az security assessment list --query "[?status.code==\'Unhealthy\']" -o table',
      'az security secure-score-controls list -o table',
    ],
  },
  CM: {
    aws: [
      'aws configservice describe-compliance-by-config-rule --output table',
      'aws configservice get-compliance-details-by-config-rule --config-rule-name <RULE> --compliance-types NON_COMPLIANT',
      'aws ssm describe-instance-information --query "InstanceInformationList[*].[InstanceId,PlatformName,PingStatus]" --output table',
      'aws ssm list-compliance-items --resource-ids <INSTANCE_ID> --resource-types ManagedInstance --filters Key=ComplianceType,Values=Patch,Type=EQUAL Key=Status,Values=NON_COMPLIANT,Type=EQUAL',
      'aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query "Reservations[*].Instances[*].[InstanceId,ImageId,LaunchTime]" --output table',
    ],
    gcp: [
      'gcloud compute instances list --format="table(name,zone,status,machineType)"',
      'gcloud asset search-all-resources --scope=projects/<PROJECT> --asset-types="compute.googleapis.com/Instance" --format=json',
      'gcloud compute instances describe <INSTANCE> --zone=<ZONE> --format="json(metadata)"',
      'gcloud container clusters describe <CLUSTER> --zone=<ZONE> --format="json(masterAuthorizedNetworksConfig,networkPolicy)"',
      'gcloud services list --enabled --format="table(config.name)"',
    ],
    azure: [
      'az policy state list --filter "complianceState eq \'NonCompliant\'" --top 25 -o table',
      'az policy state summarize --query "value[*].{policy:policyDefinitionName,nonCompliant:results.nonCompliantResources}" -o table',
      'az vm list -d --query "[*].[name,resourceGroup,powerState]" -o table',
      'az webapp config show --resource-group <RG> --name <APP> --query "{httpsOnly:httpsOnly,minTlsVersion:minTlsVersion,ftpsState:ftpsState}"',
      'az security setting list -o table',
    ],
  },
  CP: {
    aws: [
      'aws backup list-backup-plans --output table',
      'aws backup list-recovery-points-by-backup-vault --backup-vault-name Default --query "RecoveryPoints[*].[ResourceArn,Status,CompletionDate]" --output table',
      'aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,BackupRetentionPeriod,MultiAZ]" --output table',
      'aws s3api get-bucket-versioning --bucket <BUCKET>',
    ],
    gcp: [
      'gcloud sql instances list --format="table(name,settings.backupConfiguration.enabled,settings.backupConfiguration.startTime)"',
      'gcloud compute snapshots list --format="table(name,sourceDisk,creationTimestamp,status)"',
      'gcloud filestore backups list --format="table(name,sourceInstance,state)"',
    ],
    azure: [
      'az backup vault list -o table',
      'az backup item list --vault-name <VAULT> --resource-group <RG> -o table',
      'az sql db show --name <DB> --server <SERVER> --resource-group <RG> --query "{backupRetention:retentionDays,zoneRedundant:zoneRedundant}"',
    ],
  },
  IA: {
    aws: [
      'aws iam get-account-password-policy',
      'aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d | grep -v "true,.*true"  # users without MFA',
      'aws iam list-access-keys --user-name <USER> --query "AccessKeyMetadata[?CreateDate<\'2025-01-01\']"',
      'aws iam delete-access-key --user-name <USER> --access-key-id <KEY_ID>',
      'aws iam create-virtual-mfa-device --virtual-mfa-device-name <USER>-mfa --outfile /tmp/qr.png --bootstrap-method QRCodePNG',
    ],
    gcp: [
      'gcloud iam service-accounts keys list --iam-account=<SA_EMAIL> --format="table(name,validAfterTime,validBeforeTime)"',
      'gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SA_EMAIL>',
      'gcloud organizations get-iam-policy <ORG_ID> --format=json | jq \'.bindings[] | select(.members[] | contains("user:"))\'',
      'gcloud identity groups memberships search-transitive-groups --member-email=<USER_EMAIL> --labels="cloudidentity.googleapis.com/groups.discussion_forum"',
      'gcloud alpha identity groups create <GROUP_EMAIL> --organization=<ORG_ID> --group-type=security',
    ],
    azure: [
      'az ad user list --query "[?passwordPolicies==null].[displayName,userPrincipalName]" -o table',
      'az ad app credential list --id <APP_ID> --query "[?endDateTime < \'2025-06-01\']" -o table',
      'az ad sp credential reset --name <SP_NAME> --years 1',
      'az ad user update --id <USER_ID> --password <NEW_PASSWORD> --force-change-password-next-sign-in true',
      'az account get-access-token --query "{expires:expiresOn,subscription:subscription}" -o table',
    ],
  },
  IR: {
    aws: [
      'aws guardduty list-findings --detector-id <DET_ID> --finding-criteria \'{"Criterion":{"severity":{"Gte":7}}}\'',
      'aws guardduty get-findings --detector-id <DET_ID> --finding-ids <FINDING_ID>',
      'aws ssm-incidents list-incident-records --query "incidentRecordSummaries[?status==\'OPEN\']" -o table',
    ],
    gcp: [
      'gcloud scc findings list <ORG_ID> --source=<SOURCE_ID> --filter="state=ACTIVE AND severity=HIGH" --format=json',
      'gcloud alpha scc notifications list <ORG_ID> --format="table(name,description)"',
    ],
    azure: [
      'az security alert list --query "[?status==\'Active\' && alertSeverity==\'High\']" -o table',
      'az sentinel incident list --workspace-name <WS> --resource-group <RG> --query "[?status==\'New\']" -o table',
    ],
  },
  MA: {
    aws: [
      'aws ssm describe-maintenance-windows --output table',
      'aws ssm describe-maintenance-window-executions --window-id <ID> --output table',
      'aws ssm describe-instance-patch-states --instance-ids <INSTANCE_ID>',
    ],
    gcp: [
      'gcloud compute instances os-inventory describe <INSTANCE> --zone=<ZONE>',
      'gcloud compute os-config patch-deployments list --format="table(name,state)"',
    ],
    azure: [
      'az maintenance configuration list -o table',
      'az vm assess-patches --resource-group <RG> --name <VM>',
    ],
  },
  MP: {
    aws: [
      'aws s3api get-bucket-encryption --bucket <BUCKET>',
      'aws s3api get-bucket-versioning --bucket <BUCKET>',
      'aws s3api get-public-access-block --bucket <BUCKET>',
    ],
    gcp: [
      'gcloud kms keys list --location=<LOC> --keyring=<RING> --format="table(name,purpose,primary.state)"',
      'gcloud storage buckets describe gs://<BUCKET> --format="json(encryption,iamConfiguration)"',
    ],
    azure: [
      'az storage account list --query "[*].{name:name,encryption:encryption.services}" -o table',
      'az disk-encryption-set list -o table',
    ],
  },
  PE: {
    aws: ['# Physical security controls — verify via AWS Artifact compliance reports'],
    gcp: ['# Physical security controls — verify via GCP Compliance Reports Manager'],
    azure: ['# Physical security controls — verify via Azure Compliance Manager portal'],
  },
  PL: {
    aws: ['aws organizations describe-organization', 'aws organizations list-policies --filter SERVICE_CONTROL_POLICY -o table'],
    gcp: ['gcloud organizations list --format="table(name,displayName)"', 'gcloud resource-manager org-policies list --organization=<ORG_ID>'],
    azure: ['az policy definition list --management-group <MG_ID> -o table', 'az blueprints list -o table'],
  },
  PM: {
    aws: ['aws organizations describe-organization', 'aws securityhub describe-hub'],
    gcp: ['gcloud organizations list', 'gcloud scc sources list <ORG_ID>'],
    azure: ['az security center contact list -o table', 'az security pricing list -o table'],
  },
  PS: {
    aws: ['aws iam list-users --output table', 'aws iam get-user --user-name <USER>'],
    gcp: ['gcloud iam service-accounts list', 'gcloud projects get-iam-policy <PROJECT>'],
    azure: ['az ad user list -o table', 'az role assignment list --all -o table'],
  },
  PT: {
    aws: ['aws organizations list-policies --filter TAG_POLICY --output table'],
    gcp: ['gcloud resource-manager org-policies list --organization=<ORG_ID>'],
    azure: ['az policy definition list --query "[?policyType==\'Custom\']" -o table'],
  },
  RA: {
    aws: [
      'aws inspector2 list-findings --filter-criteria \'{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}\' --sort-criteria \'{"field":"SEVERITY","sortOrder":"DESC"}\' --max-results 25',
      'aws inspector2 list-coverage --filter-criteria \'{"resourceType":[{"comparison":"EQUALS","value":"AWS_EC2_INSTANCE"}]}\'',
      'aws securityhub get-findings --filters \'{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}\' --max-items 10',
    ],
    gcp: [
      'gcloud scc findings list <ORG_ID> --source="-" --filter="state=ACTIVE" --order-by="severity DESC" --format=json --limit=25',
      'gcloud container images list-tags <IMAGE> --show-occurrences --format=json',
    ],
    azure: [
      'az security assessment list --query "[?status.code==\'Unhealthy\']" -o table',
      'az security sub-assessment list --assessed-resource-id <ID> -o table',
    ],
  },
  SA: {
    aws: [
      'aws ecr describe-image-scan-findings --repository-name <REPO> --image-id imageTag=latest',
      'aws codepipeline list-pipelines --output table',
    ],
    gcp: [
      'gcloud artifacts docker images list <REPO> --include-tags --format="table(package,tags,createTime)"',
      'gcloud builds list --limit=10 --format="table(id,status,createTime)"',
    ],
    azure: [
      'az acr repository show-manifests --name <REGISTRY> --repository <REPO> -o table',
      'az pipelines list --org <ORG> --project <PROJECT> -o table',
    ],
  },
  SC: {
    aws: [
      'aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==\'0.0.0.0/0\']]].[GroupId,GroupName]" --output table',
      'aws ec2 describe-network-acls --query "NetworkAcls[*].[NetworkAclId,Entries[?RuleAction==\'allow\' && CidrBlock==\'0.0.0.0/0\']]" --output json',
      'aws elbv2 describe-listeners --load-balancer-arn <ARN> --query "Listeners[*].[Protocol,Port,SslPolicy]" --output table',
      'aws acm list-certificates --query "CertificateSummaryList[?Status==\'ISSUED\'].[DomainName,NotAfter]" --output table',
      'aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[*].[Name,ARN]" --output table',
    ],
    gcp: [
      'gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0 AND direction=INGRESS" --format="table(name,network,allowed,sourceRanges)"',
      'gcloud compute ssl-policies list --format="table(name,minTlsVersion,profile)"',
      'gcloud compute target-https-proxies list --format="table(name,sslCertificates)"',
      'gcloud compute ssl-certificates list --format="table(name,type,expireTime)"',
      'gcloud compute armor policies list --format="table(name,description)"',
    ],
    azure: [
      'az network nsg list --query "[*].{name:name,rg:resourceGroup}" -o table',
      'az network nsg rule list --nsg-name <NSG> --resource-group <RG> --query "[?access==\'Allow\' && sourceAddressPrefix==\'*\']" -o table',
      'az network application-gateway waf-policy list -o table',
      'az network front-door waf-policy list --query "[*].{name:name,mode:policySettings.mode}" -o table',
      'az keyvault certificate list --vault-name <VAULT> --query "[*].{id:id,expires:attributes.expires}" -o table',
    ],
  },
  SI: {
    aws: [
      'aws inspector2 list-findings --filter-criteria \'{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}],"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}\' --max-results 25',
      'aws ecr describe-image-scan-findings --repository-name <REPO> --image-id imageTag=latest --query "imageScanFindings.findingSeverityCounts"',
      'aws guardduty list-detectors',
      'aws ssm describe-instance-patch-states --instance-ids <INSTANCE_ID> --query "InstancePatchStates[*].[InstanceId,MissingCount,FailedCount]" --output table',
      'aws ssm send-command --instance-ids <INSTANCE_ID> --document-name "AWS-RunPatchBaseline" --parameters \'{"Operation":["Scan"]}\'',
    ],
    gcp: [
      'gcloud container images list-tags <IMAGE> --show-occurrences --occurrence-filter="kind=VULNERABILITY" --format=json',
      'gcloud scc findings list <ORG_ID> --source="-" --filter="category=VULNERABILITY AND state=ACTIVE" --format=json --limit=25',
      'gcloud compute instances os-inventory list-vulnerabilities <INSTANCE> --zone=<ZONE>',
      'gcloud artifacts docker images scan <IMAGE> --format=json',
    ],
    azure: [
      'az security assessment list --query "[?status.code==\'Unhealthy\' && contains(displayName, \'vulnerability\')]" -o table',
      'az vm run-command invoke --resource-group <RG> --name <VM> --command-id RunShellScript --scripts "apt list --upgradable 2>/dev/null | head -20"',
      'az security sub-assessment list --assessed-resource-id <ID> --assessment-name <NAME> -o table',
      'az acr task list --registry <REGISTRY> -o table',
    ],
  },
  SR: {
    aws: [
      'aws codepipeline list-pipelines --output table',
      'aws ecr get-repository-policy --repository-name <REPO>',
    ],
    gcp: [
      'gcloud artifacts repositories list --format="table(name,format)"',
      'gcloud builds list --limit=10 --format="table(id,status)"',
    ],
    azure: [
      'az acr repository list --name <REGISTRY> -o table',
      'az pipelines list --org <ORG> --project <PROJECT> -o table',
    ],
  },

  /* ── SOC 2 families ───────────────────────────────────────────────────── */
  CC: {
    aws: [
      'aws securityhub get-findings --filters \'{"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}]}\' --max-items 20',
      'aws configservice describe-compliance-by-config-rule --compliance-types NON_COMPLIANT --output table',
      'aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d',
      'aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --max-results 20',
    ],
    gcp: [
      'gcloud scc findings list <ORG_ID> --source="-" --filter="state=ACTIVE" --format=json --limit=20',
      'gcloud logging read "logName:cloudaudit.googleapis.com/activity AND protoPayload.methodName:SetIamPolicy" --limit=20',
      'gcloud projects get-iam-policy <PROJECT> --format=json',
    ],
    azure: [
      'az security assessment list --query "[?status.code==\'Unhealthy\']" -o table',
      'az monitor activity-log list --start-time $(date -u -d "-7 days" +%Y-%m-%dT%H:%M:%SZ) -o table',
      'az ad user list --query "[?accountEnabled]" -o table',
    ],
  },
  A: {
    aws: [
      'aws cloudwatch describe-alarms --state-value ALARM --output table',
      'aws elbv2 describe-target-health --target-group-arn <ARN> --output table',
      'aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,MultiAZ,DBInstanceStatus]" --output table',
    ],
    gcp: [
      'gcloud monitoring policies list --format="table(displayName,enabled)"',
      'gcloud compute instance-groups managed list --format="table(name,targetSize,zone)"',
    ],
    azure: [
      'az monitor metrics alert list -o table',
      'az vm availability-set list -o table',
      'az sql db show --name <DB> --server <SERVER> --resource-group <RG> --query "{status:status,zoneRedundant:zoneRedundant}"',
    ],
  },
  C: {
    aws: [
      'aws kms list-keys --output table',
      'aws s3api get-bucket-encryption --bucket <BUCKET>',
      'aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,StorageEncrypted]" --output table',
    ],
    gcp: [
      'gcloud kms keys list --location=<LOC> --keyring=<RING> --format="table(name,purpose,primary.state)"',
      'gcloud storage buckets describe gs://<BUCKET> --format="json(encryption)"',
    ],
    azure: [
      'az keyvault list -o table',
      'az storage account list --query "[*].{name:name,encryption:encryption.keySource}" -o table',
    ],
  },
  P: {
    aws: [
      'aws macie2 get-findings --finding-ids <ID>',
      'aws s3api get-bucket-policy --bucket <BUCKET> --output json',
    ],
    gcp: [
      'gcloud dlp inspect-content --content "<TEST>" --info-types PHONE_NUMBER,EMAIL_ADDRESS',
      'gcloud storage buckets describe gs://<BUCKET> --format="json(iamConfiguration)"',
    ],
    azure: [
      'az security data-sensitivity list -o table',
      'az storage account show --name <ACCOUNT> --query "{allowBlobPublicAccess:allowBlobPublicAccess}"',
    ],
  },
  PI: {
    aws: [
      'aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Errors --start-time <T1> --end-time <T2> --period 3600 --statistics Sum',
      'aws lambda list-functions --query "Functions[*].[FunctionName,Runtime,LastModified]" --output table',
    ],
    gcp: [
      'gcloud monitoring time-series list "metric.type=cloudfunctions.googleapis.com/function/execution_count" --filter="metric.labels.status!=ok"',
    ],
    azure: [
      'az monitor metrics list --resource <FUNC_ID> --metric "Http5xx" --interval PT1H -o table',
    ],
  },

  /* ── ISO 27001 families (A.5–A.8) ────────────────────────────────────── */
  'A.5': {
    aws: [
      'aws organizations list-policies --filter SERVICE_CONTROL_POLICY --output table',
      'aws iam list-policies --scope Local --query "Policies[*].[PolicyName,CreateDate,UpdateDate]" --output table',
    ],
    gcp: [
      'gcloud resource-manager org-policies list --organization=<ORG_ID>',
      'gcloud projects get-iam-policy <PROJECT> --format=json',
    ],
    azure: [
      'az policy definition list --management-group <MG_ID> --query "[?policyType==\'Custom\']" -o table',
      'az blueprints list -o table',
    ],
  },
  'A.6': {
    aws: ['aws iam list-users --output table', 'aws iam get-account-authorization-details --filter User'],
    gcp: ['gcloud identity groups list --organization=<ORG_ID>', 'gcloud iam service-accounts list'],
    azure: ['az ad user list -o table', 'az role assignment list --all -o table'],
  },
  'A.7': {
    aws: ['# Physical controls — verify via AWS Artifact compliance reports'],
    gcp: ['# Physical controls — verify via GCP Compliance Reports Manager'],
    azure: ['# Physical controls — verify via Azure Compliance Manager portal'],
  },
  'A.8': {
    aws: [
      'aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==\'0.0.0.0/0\']]]" --output table',
      'aws s3api get-bucket-encryption --bucket <BUCKET>',
      'aws kms list-keys --output table',
      'aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,PubliclyAccessible]" --output table',
    ],
    gcp: [
      'gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0" --format="table(name,allowed,sourceRanges)"',
      'gcloud kms keys list --location=<LOC> --keyring=<RING>',
      'gcloud sql instances list --format="table(name,ipAddresses,settings.ipConfiguration.requireSsl)"',
    ],
    azure: [
      'az network nsg rule list --nsg-name <NSG> --resource-group <RG> --query "[?access==\'Allow\' && sourceAddressPrefix==\'*\']" -o table',
      'az keyvault list -o table',
      'az sql server list --query "[*].{name:name,publicNetworkAccess:publicNetworkAccess}" -o table',
    ],
  },

  /* ── HIPAA families (§164.3xx) ────────────────────────────────────────── */
  '164.308': {
    aws: [
      'aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d',
      'aws iam get-account-password-policy',
      'aws guardduty list-detectors',
      'aws cloudtrail describe-trails --output table',
      'aws ssm-incidents list-incident-records -o table',
    ],
    gcp: [
      'gcloud iam service-accounts list --format="table(email,disabled)"',
      'gcloud projects get-iam-policy <PROJECT> --format=json | jq ".bindings"',
      'gcloud scc findings list <ORG_ID> --source="-" --filter="state=ACTIVE" --limit=20',
      'gcloud logging sinks list --format="table(name,destination)"',
    ],
    azure: [
      'az ad user list --query "[?accountEnabled]" -o table',
      'az security alert list --query "[?status==\'Active\']" -o table',
      'az monitor diagnostic-settings list --resource <RESOURCE_ID> -o table',
      'az ad conditional-access policy list -o table',
    ],
  },
  '164.310': {
    aws: ['# Physical safeguards — verify via AWS SOC 2 reports in AWS Artifact'],
    gcp: ['# Physical safeguards — verify via GCP Compliance Reports Manager'],
    azure: ['# Physical safeguards — verify via Azure Compliance Manager'],
  },
  '164.312': {
    aws: [
      'aws kms list-keys --output table',
      'aws s3api get-bucket-encryption --bucket <BUCKET>',
      'aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId]" --output table',
      'aws iam list-mfa-devices --user-name <USER>',
      'aws cloudtrail get-trail-status --name <TRAIL>',
    ],
    gcp: [
      'gcloud kms keys list --location=<LOC> --keyring=<RING> --format="table(name,purpose,primary.state)"',
      'gcloud sql instances list --format="table(name,settings.ipConfiguration.requireSsl,settings.dataDiskType)"',
      'gcloud logging read "logName:cloudaudit.googleapis.com/data_access" --limit=25',
    ],
    azure: [
      'az keyvault list -o table',
      'az disk-encryption-set list -o table',
      'az sql db tde show --server <SERVER> --database <DB> --resource-group <RG>',
      'az monitor activity-log list --start-time $(date -u -d "-7 days" +%Y-%m-%dT%H:%M:%SZ) -o table',
    ],
  },
  '164.314': {
    aws: [
      'aws organizations list-accounts --output table',
      'aws ram list-resources --resource-owner SELF --output table',
    ],
    gcp: [
      'gcloud projects list --format="table(projectId,name)"',
      'gcloud iam service-accounts list --format="table(email)"',
    ],
    azure: [
      'az account list --all -o table',
      'az role assignment list --all --query "[?principalType==\'ServicePrincipal\']" -o table',
    ],
  },
  '164.316': {
    aws: ['aws configservice describe-config-rules --output table', 'aws securityhub describe-hub'],
    gcp: ['gcloud resource-manager org-policies list --organization=<ORG_ID>', 'gcloud scc sources list <ORG_ID>'],
    azure: ['az policy assignment list -o table', 'az security center contact list -o table'],
  },
};

// Map CMMC L2 family prefixes to their NIST equivalents (CMMC derives from 800-171 → 800-53)
const CMMC_TO_NIST_FAMILY: Record<string, string> = {
  'AC': 'AC', 'AT': 'AT', 'AU': 'AU', 'CM': 'CM', 'IA': 'IA',
  'IR': 'IR', 'MA': 'MA', 'MP': 'MP', 'PS': 'PS', 'PE': 'PE',
  'RA': 'RA', 'CA': 'CA', 'SC': 'SC', 'SI': 'SI',
};

/**
 * Resolve the control family key used in CLI_COMMANDS lookup.
 * Handles NIST (AC-1), SOC2 (CC1.1), ISO (A.5.1), HIPAA (164.308(a)),
 * and CMMC (AC.L2-3.1.1) formats.
 */
function resolveFamily(controlId: string): string {
  // CMMC: AC.L2-3.1.1 → AC → mapped via CMMC_TO_NIST_FAMILY
  if (controlId.includes('.L2')) {
    const prefix = controlId.split('.')[0];
    return CMMC_TO_NIST_FAMILY[prefix] || prefix;
  }
  // HIPAA: 164.308(a)(1) → 164.308
  const hipaaMatch = controlId.match(/^(164\.\d+)/);
  if (hipaaMatch) return hipaaMatch[1];
  // ISO 27001: A.5.1 → A.5
  if (controlId.startsWith('A.')) {
    const parts = controlId.split('.');
    return `${parts[0]}.${parts[1]}`;
  }
  // SOC2: CC1.1 → CC, A1.1 → A, PI1.2 → PI
  const soc2Match = controlId.match(/^([A-Z]+)\d/);
  if (soc2Match) return soc2Match[1];
  // NIST: AC-1 → AC
  return controlId.split('-')[0];
}

function getRemediationData(controlId: string, _assertion: string, provider: string): RemediationData {
  const family = resolveFamily(controlId);
  const p = provider?.toLowerCase() || 'aws';

  const familyCommands = CLI_COMMANDS[family];
  const cli = familyCommands?.[p] || familyCommands?.['aws'] || [];

  // Prose steps keyed by family — shorter and actionable now
  const steps: Record<string, string[]> = {
    AC: [
      `Audit all accounts and roles with access to resources in scope for ${controlId}.`,
      'Disable or remove accounts inactive for 90+ days.',
      'Enforce MFA on all privileged accounts (TOTP, FIDO2, or hardware key).',
      'Configure automated access reviews on a 90-day cycle.',
    ],
    AT: [
      `Verify security awareness training completion for all personnel under ${controlId}.`,
      'Schedule role-based training for privileged users within 30 days.',
    ],
    AU: [
      `Verify audit logging is active for all resources in scope for ${controlId}.`,
      'Set log retention to minimum 365 days per policy.',
      'Create alert rules for auth failures, privilege escalations, and API key usage.',
      'Run quarterly log integrity verification.',
    ],
    CA: [
      `Review most recent security assessment results for ${controlId}.`,
      'Remediate all critical and high findings within SLA.',
      'Schedule follow-up assessment within 12 months.',
    ],
    CM: [
      `Create a documented CIS Benchmark Level 2 baseline for affected resources.`,
      'Enable configuration drift detection.',
      'Remediate all deviations from the approved baseline.',
      'Establish change control requiring security review.',
    ],
    CP: [
      'Verify backup schedule meets RPO/RTO requirements.',
      'Test restore from backup within the last 90 days.',
      'Ensure cross-region replication is enabled for critical data.',
    ],
    IA: [
      `Enroll all accounts under ${controlId} in MFA.`,
      'Rotate all API keys and credentials older than 90 days.',
      'Remove shared/service accounts without documented justification.',
      'Enable just-in-time (JIT) access for privileged operations.',
    ],
    IR: [
      'Review and update the incident response plan.',
      'Verify alerting thresholds for critical security events.',
      'Conduct tabletop exercise within 30 days.',
    ],
    MA: [
      'Verify all systems are on a documented maintenance schedule.',
      'Apply pending security patches within SLA.',
      'Document all maintenance windows and approvals.',
    ],
    MP: [
      'Verify encryption at rest for all storage media.',
      'Review and restrict public access to storage buckets/blobs.',
      'Audit key management policies and rotation schedules.',
    ],
    PE: [
      'Verify physical access controls via provider compliance reports.',
      'Review badge access logs for sensitive areas.',
    ],
    PL: [
      'Review and update security planning documents.',
      'Ensure all organizational policies are current and approved.',
    ],
    PM: [
      'Verify program management controls are documented.',
      'Review security program metrics and reporting.',
    ],
    PS: [
      'Verify personnel screening for all users with system access.',
      'Review access termination procedures and timeliness.',
    ],
    PT: [
      'Review PII processing policies and consent mechanisms.',
      'Verify data minimization practices.',
    ],
    RA: [
      `Run a full vulnerability scan for systems in scope for ${controlId}.`,
      'Prioritize by risk: critical ≤ 24h, high ≤ 7d, medium ≤ 30d.',
      'Document accepted risks with CISO sign-off.',
    ],
    SA: [
      'Review supply chain and development lifecycle controls.',
      'Verify container image scanning in CI/CD pipeline.',
    ],
    SC: [
      `Review network security rules for resources under ${controlId}.`,
      'Enforce TLS 1.2+ on all endpoints; disable TLS 1.0/1.1.',
      'Enable encryption at rest (AES-256) for all data stores.',
      'Deploy WAF for all public-facing applications.',
      'Remove firewall rules allowing 0.0.0.0/0 ingress.',
    ],
    SI: [
      `Scan all systems under ${controlId} for vulnerabilities.`,
      'Remediate CVSS ≥ 9.0 findings within 24 hours.',
      'Ensure EDR/AV agents are deployed and current.',
      'Add vulnerability scanning as a CI/CD blocking gate.',
    ],
    SR: [
      'Review supply chain risk management controls.',
      'Verify artifact integrity and provenance.',
    ],
    // SOC 2
    CC: [
      `Review common criteria controls for ${controlId}.`,
      'Verify access controls, change management, and risk mitigation.',
      'Run a credential and access audit.',
    ],
    A: [
      'Verify system availability meets SLA targets.',
      'Review monitoring alerts and auto-scaling configurations.',
      'Test failover and disaster recovery procedures.',
    ],
    C: [
      'Verify encryption at rest and in transit for all sensitive data.',
      'Review key management and rotation policies.',
    ],
    P: [
      'Review data privacy policies and data classification.',
      'Verify PII handling meets privacy notice commitments.',
    ],
    PI: [
      'Verify processing integrity controls and error handling.',
      'Review data validation and quality assurance procedures.',
    ],
    // ISO 27001
    'A.5': [
      'Review organizational security policies and ensure current approval.',
      'Verify policy distribution and acknowledgment by all personnel.',
    ],
    'A.6': [
      'Verify personnel security screening and training.',
      'Review user access provisioning and de-provisioning processes.',
    ],
    'A.7': [
      'Verify physical security controls via provider compliance documentation.',
      'Review facility access logs and visitor management.',
    ],
    'A.8': [
      'Review technological controls: network security, encryption, access management.',
      'Verify firewall rules, TLS enforcement, and key management.',
      'Audit database and storage encryption settings.',
    ],
    // HIPAA
    '164.308': [
      'Review administrative safeguards: access management, security awareness, incident response.',
      'Verify workforce training completion and risk analysis documentation.',
      'Audit security incident procedures and contingency plans.',
    ],
    '164.310': [
      'Verify physical safeguards via provider compliance reports (SOC 2, ISO 27001).',
      'Review workstation and device security policies.',
    ],
    '164.312': [
      'Verify access controls: unique user IDs, emergency access, auto-logoff, encryption.',
      'Audit transmission security (TLS) and integrity controls.',
      'Review audit logs for ePHI access.',
    ],
    '164.314': [
      'Review business associate agreements (BAAs) for all vendors with ePHI access.',
      'Verify organizational requirements and documentation.',
    ],
    '164.316': [
      'Review documentation and policies for HIPAA compliance.',
      'Verify policy retention (6 years) and update procedures.',
    ],
  };

  return {
    steps: steps[family] || [`Review the control requirements for ${controlId}.`, 'Identify and remediate any gaps.', 'Document findings and assign owners.'],
    cli,
  };
}

export default function AssessmentsPage() {
  const queryClient = useQueryClient();
  const [selectedFramework, setSelectedFramework] = useState('nist_800_53');
  const [selectedRun, setSelectedRun] = useState<AssessmentRun | null>(null);
  const [selectedResult, setSelectedResult] = useState<AssessmentResult | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'pass' | 'fail'>('all');

  const { data: runs, isLoading } = useQuery<AssessmentRun[]>({
    queryKey: ['assessments', 'runs'],
    queryFn: async () => (await api.get('/assessments/runs')).data,
    refetchInterval: 10000,
  });

  const triggerMutation = useMutation({
    mutationFn: async () => (await api.post('/assessments/run', {
      framework: selectedFramework,
      providers: ['aws', 'azure', 'gcp'],
    })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['assessments', 'runs'] }),
  });

  const { data: runResults } = useQuery<AssessmentResult[]>({
    queryKey: ['assessments', 'results', selectedRun?.id],
    queryFn: async () => (await api.get(`/assessments/runs/${selectedRun!.id}/results`)).data,
    enabled: !!selectedRun,
  });

  const results = runResults ?? [];
  const filteredResults = results.filter(r =>
    statusFilter === 'all' ? true : r.status === statusFilter
  );

  const passCount = results.filter(r => r.status === 'pass').length;
  const failCount = results.filter(r => r.status === 'fail').length;

  const fw = Object.entries(FRAMEWORK_LABELS);

  const formatDate = (d: string | null) => d ? new Date(d).toLocaleString() : 'In progress…';

  const statusIcon = (status: string) => {
    if (status === 'completed') return <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />;
    if (status === 'failed') return <XCircle className="w-3.5 h-3.5 text-red-400" />;
    return <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />;
  };

  const severityBadge = (sev: string) => {
    const map: Record<string, string> = {
      critical: 'bg-red-500/15 text-red-400 border-red-500/20',
      high:     'bg-orange-500/15 text-orange-400 border-orange-500/20',
      medium:   'bg-amber-500/15 text-amber-400 border-amber-500/20',
      low:      'bg-blue-500/15 text-blue-400 border-blue-500/20',
    };
    return `${map[sev] || 'bg-slate-500/15 text-slate-400 border-slate-500/20'} text-[10px] font-bold px-1.5 py-0.5 rounded border`;
  };

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)]">Assessments</h2>
          <p className="text-slate-400 text-sm mt-0.5">Run and view compliance checks across your infrastructure</p>
        </div>
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <select
            value={selectedFramework}
            onChange={e => setSelectedFramework(e.target.value)}
            className="flex-1 sm:flex-none bg-[var(--bg-interactive)] border border-[var(--border-color)] text-[var(--text-heading)] text-sm rounded-xl px-3 py-2.5 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          >
            {fw.map(([id, label]) => <option key={id} value={id} className="bg-[var(--bg-surface)]">{label}</option>)}
          </select>
          <button
            onClick={() => triggerMutation.mutate()}
            disabled={triggerMutation.isPending}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-semibold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20 disabled:opacity-50 whitespace-nowrap"
          >
            {triggerMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Trigger Run
          </button>
        </div>
      </div>

      <div className={`grid gap-5 ${selectedRun ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
        {/* Run list */}
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
          <div className="px-5 py-3 border-b border-[var(--border-color)] flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[var(--text-heading)]">Assessment Runs</h3>
            {isLoading && <Loader2 className="w-4 h-4 animate-spin text-slate-500" />}
          </div>

          <div className="overflow-auto max-h-[600px] scrollbar-thin">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[var(--bg-surface)] border-b border-[var(--border-color)]">
                <tr>
                  {['Framework', 'Date', 'Status', 'Checks', 'Pass Rate'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-slate-500 font-semibold uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {runs?.map(run => (
                  <tr
                    key={run.id}
                    onClick={() => { setSelectedRun(run); setSelectedResult(null); setStatusFilter('all'); }}
                    className={`cursor-pointer transition-colors ${selectedRun?.id === run.id ? 'bg-blue-500/10 border-l-2 border-l-blue-500' : 'hover:bg-[var(--bg-subtle)]'}`}
                  >
                    <td className="px-4 py-3 font-semibold text-[var(--text-heading)]">{FRAMEWORK_LABELS[run.framework] || run.framework}</td>
                    <td className="px-4 py-3 text-slate-400">{formatDate(run.started_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {statusIcon(run.status)}
                        <span className={`capitalize font-medium ${run.status === 'completed' ? 'text-emerald-400' : run.status === 'failed' ? 'text-red-400' : 'text-blue-400'}`}>
                          {run.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-400">{run.total_checks || '—'}</td>
                    <td className="px-4 py-3">
                      {run.pass_rate != null ? (
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-[var(--bg-interactive-hover)] rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${run.pass_rate >= 80 ? 'bg-emerald-500' : run.pass_rate >= 60 ? 'bg-amber-500' : 'bg-red-500'}`}
                              style={{ width: `${run.pass_rate}%` }}
                            />
                          </div>
                          <span className={`font-bold ${run.pass_rate >= 80 ? 'text-emerald-400' : run.pass_rate >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
                            {run.pass_rate.toFixed(1)}%
                          </span>
                        </div>
                      ) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Results panel */}
        {selectedRun && (
          <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden flex flex-col">
            <div className="px-5 py-3 border-b border-[var(--border-color)] flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text-heading)] flex items-center gap-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  {FRAMEWORK_LABELS[selectedRun.framework]} Results
                </h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  {passCount} passed · {failCount} failed · {formatDate(selectedRun.started_at)}
                </p>
              </div>
              <button onClick={() => { setSelectedRun(null); setSelectedResult(null); }} className="p-1.5 hover:bg-[var(--bg-interactive)] rounded-lg text-slate-500 hover:text-[var(--text-heading)] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Filter tabs */}
            <div className="flex gap-1 px-4 py-2 border-b border-[var(--border-subtle)]">
              {(['all', 'fail', 'pass'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => { setStatusFilter(f); setSelectedResult(null); }}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors ${
                    statusFilter === f ? 'bg-blue-500/20 text-blue-400 border border-blue-500/20' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {f === 'all' ? `All (${results.length})` : f === 'fail' ? `Failing (${failCount})` : `Passing (${passCount})`}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-auto max-h-[520px] scrollbar-thin divide-y divide-[var(--border-subtle)]">
              {filteredResults.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                  <CheckCircle className="w-8 h-8 mb-2 text-emerald-500/40" />
                  <p className="text-sm">No results in this category</p>
                </div>
              ) : filteredResults.map(result => (
                <div key={result.id} className="group">
                  <button
                    onClick={() => setSelectedResult(selectedResult?.id === result.id ? null : result)}
                    className={`w-full text-left px-4 py-3 hover:bg-[var(--bg-subtle)] transition-colors flex items-start gap-3 ${selectedResult?.id === result.id ? 'bg-[var(--bg-interactive)]' : ''}`}
                  >
                    <div className="flex-shrink-0 mt-0.5">
                      {result.status === 'pass'
                        ? <CheckCircle className="w-4 h-4 text-emerald-400" />
                        : result.severity === 'critical' || result.severity === 'high'
                          ? <XCircle className="w-4 h-4 text-red-400" />
                          : <AlertTriangle className="w-4 h-4 text-amber-400" />
                      }
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-bold text-xs text-blue-400">{result.control_id}</span>
                        <span className="text-slate-600 text-[10px]">{result.check_id?.split('.').pop()}</span>
                        {result.status === 'fail' && <span className={severityBadge(result.severity)}>{result.severity}</span>}
                      </div>
                      <p className="text-xs text-slate-400 leading-tight line-clamp-2">{result.assertion}</p>
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-600">
                        <span className="uppercase font-semibold">{result.provider}</span>
                        <span>·</span>
                        <span>{result.region}</span>
                      </div>
                    </div>
                    <ChevronRight className={`w-3.5 h-3.5 text-slate-600 flex-shrink-0 transition-transform ${selectedResult?.id === result.id ? 'rotate-90' : ''}`} />
                  </button>

                  {/* Expanded remediation */}
                  {selectedResult?.id === result.id && result.status === 'fail' && (() => {
                    const rem = getRemediationData(result.control_id, result.assertion, result.provider);
                    return (
                    <div className="px-4 pb-4 space-y-3 bg-[var(--bg-subtle)]">
                      {result.findings.length > 0 && (
                        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3">
                          <p className="text-xs font-bold text-red-400 mb-2 flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5" /> Findings
                          </p>
                          {result.findings.map((f, i) => (
                            <p key={i} className="text-xs text-red-300 leading-relaxed">• {f}</p>
                          ))}
                        </div>
                      )}
                      <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-3">
                        <p className="text-xs font-bold text-blue-400 mb-3 flex items-center gap-1.5">
                          <BookOpen className="w-3.5 h-3.5" /> Recommended Remediation
                        </p>
                        <ol className="space-y-2">
                          {rem.steps.map((step, i) => (
                            <li key={i} className="flex gap-2.5 text-xs text-slate-300 leading-relaxed">
                              <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center font-bold text-blue-400 text-[10px]">{i + 1}</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                      {rem.cli.length > 0 && (
                        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-3">
                          <div className="flex items-center justify-between mb-3">
                            <p className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                              <Terminal className="w-3.5 h-3.5" /> {result.provider?.toUpperCase()} CLI Commands
                            </p>
                            <button
                              onClick={() => { navigator.clipboard.writeText(rem.cli.join('\n')); }}
                              className="flex items-center gap-1 text-[10px] text-emerald-500 hover:text-emerald-300 transition-colors"
                              title="Copy all commands"
                            >
                              <Copy className="w-3 h-3" /> Copy All
                            </button>
                          </div>
                          <div className="space-y-1.5">
                            {rem.cli.map((cmd, i) => (
                              <div key={i} className="group/cmd flex items-start gap-2">
                                <span className="flex-shrink-0 text-emerald-600 text-[10px] font-mono mt-0.5 select-none">$</span>
                                <code className="text-[11px] text-emerald-300 font-mono leading-relaxed break-all flex-1">{cmd}</code>
                                <button
                                  onClick={() => navigator.clipboard.writeText(cmd)}
                                  className="flex-shrink-0 opacity-0 group-hover/cmd:opacity-100 transition-opacity p-0.5"
                                  title="Copy command"
                                >
                                  <Copy className="w-2.5 h-2.5 text-emerald-600 hover:text-emerald-400" />
                                </button>
                              </div>
                            ))}
                          </div>
                          <div className="mt-3 pt-3 border-t border-emerald-500/10 text-[10px] text-emerald-600">
                            Replace &lt;PLACEHOLDERS&gt; with your actual resource identifiers
                          </div>
                        </div>
                      )}
                      <div className="flex items-center gap-1.5 text-[10px] text-slate-600">
                        <Info className="w-3 h-3" />
                        Control: {result.control_id} · Check: {result.check_id} · Provider: {result.provider?.toUpperCase()} · Region: {result.region}
                      </div>
                    </div>
                    );
                  })()}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
