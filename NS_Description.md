# NeuraShield: AI-Powered Low-Cost IDS/IPS & Automated Incident Response Platform

## Project Overview

NeuraShield is a modular, AI-assisted cybersecurity platform that combines **Network Traffic Monitoring**, **Intrusion Detection (IDS)**, **Intrusion Prevention (IPS)**, **Machine Learning**, **Automated Incident Response**, **Digital Forensics**, and **Security Monitoring** into a single lightweight system designed for small and medium-sized organizations.

The project aims to provide enterprise-inspired cybersecurity capabilities using open-source technologies while remaining affordable and deployable on low-cost hardware.

Unlike traditional student projects that focus on only one cybersecurity concept (such as packet sniffing, intrusion detection, machine learning, or digital forensics), NeuraShield integrates multiple cybersecurity domains into a complete security workflow.

The platform is intended as a research-grade prototype demonstrating practical applications of Networking, Cybersecurity, Machine Learning, Linux System Administration, Backend Development, Digital Forensics, Incident Response, and Security Monitoring.

---

# Problem Statement

Commercial Intrusion Detection and Prevention Systems are expensive and often inaccessible to educational institutions, startups, research laboratories, and small businesses.

Many organizations therefore operate with:

* No continuous network monitoring
* No intrusion detection
* No automatic attack prevention
* No centralized incident logging
* No forensic evidence preservation

As a result, cyberattacks often remain undetected until significant damage has already occurred.

NeuraShield addresses this problem by providing a lightweight, modular, AI-assisted security platform capable of detecting, preventing, documenting, and reporting cyber incidents in real time.

---

# Primary Objectives

The platform aims to:

1. Monitor live network traffic continuously.
2. Detect malicious network behavior using both rule-based detection and machine learning.
3. Automatically respond to attacks by blocking malicious hosts.
4. Preserve digital evidence for forensic investigations.
5. Maintain cryptographic integrity of forensic artifacts.
6. Provide centralized monitoring through a web dashboard.
7. Generate automated incident reports and security alerts.

---

# Core Functional Philosophy

The project follows a complete security lifecycle rather than implementing isolated security components.

The workflow follows the standard incident response process:

Observe
↓

Analyze
↓

Detect
↓

Classify
↓

Respond
↓

Collect Evidence
↓

Preserve Integrity
↓

Notify Administrator
↓

Generate Report

Every module performs one specific responsibility.

Together they form a complete security platform.

---

# High-Level System Architecture

Network Traffic
↓

Packet Capture Engine
↓

Packet Queue
↓

Flow Aggregator
↓

Detection Engine
↓

Rule-Based Detection
+
Machine Learning Detection
↓

Threat Decision Engine
↓

Intrusion Prevention System
↓

Automated Incident Response
↓

Digital Forensics Module
↓

Evidence Integrity Verification
↓

Incident Database
↓

Dashboard API
↓

Web Dashboard
↓

Report Generator
↓

Alert Notification System

---

# Technical Pipeline

## Stage 1 — Live Network Monitoring

The platform continuously monitors a selected network interface.

Incoming and outgoing packets are captured in real time.

Captured information includes:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* Packet Size
* TCP Flags
* Timestamp

Payload inspection is intentionally minimal because behavioral analysis relies primarily on metadata.

Purpose:

Provide real-time visibility into network communications.

Technology:

* Python
* Scapy

---

## Stage 2 — Packet Queue

Captured packets are placed into a thread-safe queue.

Reason:

Packet capture should never stop because another module is busy processing data.

The queue decouples packet capture from analysis.

Technology:

* Python queue
* Threading

---

## Stage 3 — Flow Aggregation

Individual packets have limited analytical value.

Instead, packets are grouped into network flows.

A flow is identified using the standard 5-tuple:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol

Packets belonging to the same flow are aggregated over a configurable time window (typically five seconds).

Flow features include:

* Flow Duration
* Total Packets
* Total Bytes
* Packet Rate
* Average Packet Size
* SYN Count
* ACK Count
* Unique Destination Ports
* Protocol
* Connection Frequency

The generated flow becomes the primary input for the detection engine.

Technology:

* Python
* Dictionaries
* Sliding Windows

---

## Stage 4 — Rule-Based Detection Engine

Before introducing Artificial Intelligence, NeuraShield first performs deterministic detection using manually designed security rules.

Example attacks:

Port Scan

Rule:

One source IP contacts more than twenty unique destination ports within five seconds.

SYN Flood

Rule:

Excessive SYN packets within a short period.

Brute Force

Rule:

Repeated authentication attempts exceeding configured thresholds.

This stage provides:

* Fast detection
* Low computational cost
* Explainable logic
* Reliable baseline security

Technology:

Pure Python.

---

## Stage 5 — Machine Learning Engine

After rule-based detection is operational, Machine Learning enhances threat classification.

Public datasets are used for training.

Examples:

* CICIDS2017
* UNSW-NB15

The model learns patterns associated with:

* Normal Traffic
* Port Scan
* Brute Force
* DoS
* DDoS
* DNS Tunneling

The current planned algorithm is:

Random Forest

Reasons:

* Fast inference
* High accuracy
* Easy explainability
* Suitable for tabular network data

Model pipeline:

Dataset
↓

Cleaning

↓

Feature Selection

↓

Training

↓

Evaluation

↓

Model Export

↓

Real-Time Prediction

Technology:

* Pandas
* NumPy
* Scikit-Learn
* Joblib

---

## Stage 6 — Explainable AI

Instead of simply returning:

Threat Detected

NeuraShield provides:

Threat Type

Reason

Confidence

Example:

Threat:
Port Scan

Reason:

42 destination ports contacted in four seconds.

Confidence:

96%

This improves administrator understanding and debugging.

---

## Stage 7 — Threat Decision Engine

The outputs of the Rule Engine and Machine Learning Engine are combined.

Decision logic determines:

* Threat severity
* Confidence
* Required action

Possible actions:

* Ignore
* Log
* Alert
* Temporary Block
* Permanent Block

---

## Stage 8 — Intrusion Prevention System

Once a malicious host is confirmed,

NeuraShield automatically performs prevention.

Possible actions:

* Block Source IP
* Temporary Quarantine
* Permanent Blacklist
* Remove Firewall Rule after timeout

Firewall interaction is performed through Linux firewall utilities.

Technology:

iptables

(or nftables in future versions)

---

## Stage 9 — Automated Incident Response

Incident response begins immediately after threat confirmation.

Tasks include:

* Create Incident Record
* Preserve Evidence
* Execute Firewall Action
* Generate Alert
* Update Dashboard

This removes the need for manual administrator intervention.

---

## Stage 10 — Digital Forensics Module

This module focuses on evidence preservation.

Information collected includes:

* Timestamp
* Source IP
* Destination IP
* Ports
* Protocol
* Threat Type
* Detection Method
* Action Taken

Where feasible, the relevant packet capture is preserved as a PCAP file.

Purpose:

Support post-incident investigation.

---

## Stage 11 — Evidence Integrity

Every forensic artifact receives a SHA-256 cryptographic hash.

This ensures:

* Evidence Integrity
* Tamper Detection
* Chain of Custody Verification

Technology:

Python hashlib

---

## Stage 12 — Incident Database

Every incident is permanently stored.

Database tables include:

Incidents

Evidence

Blocked IPs

System Statistics

Future User Management

Database:

SQLite

Future:

PostgreSQL

---

## Stage 13 — Backend API

A REST API exposes platform information.

Endpoints include:

/api/incidents

/api/threats

/api/statistics

/api/blocked

Purpose:

Provide data for the dashboard.

Technology:

FastAPI

---

## Stage 14 — Dashboard

Administrators monitor the system using a web interface.

Dashboard components include:

System Status

Threat Counter

Blocked Hosts

Recent Incidents

Threat Timeline

Attack Distribution

Traffic Statistics

Charts

Technology:

HTML

CSS

JavaScript

Chart.js

---

## Stage 15 — Report Generation

Every confirmed incident can generate a structured PDF report.

Contents:

Incident Summary

Attack Details

Timeline

Response Action

Evidence Reference

SHA-256 Hash

Technology:

ReportLab

---

## Stage 16 — Notification System

Critical incidents immediately notify administrators.

Current plan:

Telegram Bot

Future:

Email

Desktop Notifications

---

# Complete Runtime Workflow

Attacker

↓

Network Traffic

↓

Packet Capture

↓

Packet Queue

↓

Flow Aggregation

↓

Feature Extraction

↓

Rule Engine

↓

Machine Learning Engine

↓

Threat Decision

↓

Intrusion Prevention

↓

Incident Response

↓

Evidence Collection

↓

SHA-256 Integrity

↓

SQLite Database

↓

Dashboard Update

↓

PDF Report

↓

Telegram Notification

---

# Project Modules

1. Packet Capture Engine

2. Queue Manager

3. Flow Aggregator

4. Rule-Based Detection Engine

5. Machine Learning Engine

6. Explainable AI Module

7. Threat Decision Engine

8. Intrusion Prevention System

9. Incident Response Engine

10. Digital Forensics Module

11. Evidence Integrity Module

12. Database Layer

13. REST API Backend

14. Web Dashboard

15. Report Generator

16. Notification Engine

---

# Technology Stack

Programming Language

Python

Operating System

Ubuntu Linux

Packet Capture

Scapy

Flow Processing

Python

Rule Engine

Python

Machine Learning

Scikit-Learn

Data Processing

Pandas

NumPy

Dataset

CICIDS2017

UNSW-NB15

Database

SQLite

Backend

FastAPI

Frontend

HTML

CSS

JavaScript

Charts

Chart.js

Firewall

iptables

Evidence Integrity

SHA-256 (hashlib)

Report Generation

ReportLab

Alerts

Telegram Bot API

Version Control

Git

GitHub

Testing

Wireshark

Nmap

Kali Linux

Ubuntu Virtual Machines

---

# Development Philosophy

The project will **not** be built as one large application.

Instead, it will be developed incrementally.

Phase 1:
Network Monitoring

↓

Phase 2:
Flow Processing

↓

Phase 3:
Rule-Based IDS

↓

Phase 4:
Intrusion Prevention

↓

Phase 5:
Digital Forensics

↓

Phase 6:
Dashboard Backend

↓

Phase 7:
Dashboard Frontend

↓

Phase 8:
Machine Learning

↓

Phase 9:
Explainable AI

↓

Phase 10:
Integration, Testing, Optimization, Documentation

Each phase must be fully completed and tested before beginning the next phase.

---

# Scope

The project is intended to demonstrate:

* Network Packet Capture
* Network Flow Analysis
* Rule-Based Intrusion Detection
* Machine Learning-Based Threat Classification
* Automated Firewall Control
* Incident Response Automation
* Digital Evidence Preservation
* Cryptographic Evidence Integrity
* REST API Development
* Security Dashboard Development
* Automated Reporting
* Real-Time Alerting

It is **not** intended to replace commercial enterprise security products but to serve as a functional, modular, and extensible cybersecurity research prototype that integrates networking, cybersecurity, machine learning, digital forensics, and incident response into a unified platform.

