 Azure Sentinel Detection Engineering Lab
 Project Overview

This lab simulates a Security Operations Center (SOC) use case using Microsoft Sentinel.

The objective is to detect brute-force login activity using KQL (Kusto Query Language) and generate incidents for investigation.

 Lab Architecture

Cloud Platform: Microsoft Azure

SIEM: Microsoft Sentinel

Log Sources: Entra ID

Tables Used: SignInLogs, AuditLogs

Detection Type: Scheduled Analytics Rule

 Detection Use Case – Brute Force Attack
 Detection Logic
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
 MITRE ATT&CK Mapping

Initial Access

Brute Force (T1110)

 Incident Workflow

Multiple failed logins simulated

Analytics rule triggered

Incident generated in Sentinel

Entity mapping reviewed

Investigation timeline analyzed

 Evidence
Analytics Rule

Detection Query Result

Incident Triggered
