Azure Sentinel Detection Engineering Lab

Overview

# This project demonstrates the implementation of a custom detection use case in Microsoft Sentinel using Microsoft Entra ID logs.
# The objective is to simulate brute-force authentication attempts and validate the full incident lifecycle — from log ingestion to detection and investigation.

Environment

# Cloud Platform
# Microsoft Azure

SIEM

# Microsoft Sentinel

Identity Source

# Microsoft Entra ID

Log Tables Used

# SignInLogs
# AuditLogs

Detection Type

# Scheduled Analytics Rule

Detection Scenario

# Brute-Force Authentication Attempt
Brute-force attacks involve repeated failed login attempts in order to gain unauthorized access to user accounts.
This detection identifies excessive failed authentication attempts from a single IP address within a five-minute window.

Detection Logic (KQL)

# SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5

Logic Explanation

# Filters failed sign-in attempts
# Aggregates failures by IP and user
# Evaluates activity in 5-minute intervals
# Triggers when threshold (≥ 5 failures) is exceeded


Rule Type: Scheduled Query

Severity: Medium

Query Frequency: 5 minutes

Lookup Period: 5 minutes

Incident Creation: Enabled

Incident Lifecycle

# Multiple failed login attempts were simulated.
# The analytics rule evaluated incoming SignInLogs.
# Threshold condition was met.
# An incident was automatically generated.
# Entity mapping and timeline were reviewed during investigation.

Evidence

# Analytics Rule Configuration
# Query Results
# Incident Generated
