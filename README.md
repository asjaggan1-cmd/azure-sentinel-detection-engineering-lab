 Azure Sentinel Detection Engineering Lab
1. Project Overview

This lab simulates a Security Operations Center (SOC) use case using Microsoft Sentinel.

The objective is to detect brute-force login activity using Kusto Query Language (KQL) and generate incidents for investigation.

2. Lab Architecture
Cloud Platform

Microsoft Azure

SIEM

Microsoft Sentinel

Identity Provider

Microsoft Entra ID

Log Sources

SignInLogs

AuditLogs

Detection Type

Scheduled Analytics Rule

3. Detection Use Case: Brute Force Attack
3.1 Detection Logic
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5

This query identifies multiple failed login attempts from the same IP address within a five-minute window.

3.2 MITRE ATT&CK Mapping

Tactic: Initial Access

Technique: Brute Force (T1110)

4. Analytics Rule Configuration

Rule Type: Scheduled Query Rule

Severity: Medium

Query Frequency: 5 minutes

Lookup Period: 5 minutes

Incident Creation: Enabled

5. Incident Workflow

Multiple failed login attempts were simulated.

The analytics rule evaluated SignInLogs.

The rule threshold condition was met.

An incident was generated in Microsoft Sentinel.

Entity mapping and timeline were reviewed during investigation.

6. Evidence
6.1 Analytics Rule

6.2 Detection Query Results

6.3 Incident Triggered
