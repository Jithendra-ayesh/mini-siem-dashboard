# 🛡 Mini SIEM Dashboard

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5-purple?logo=bootstrap)
![Status](https://img.shields.io/badge/Status-Completed-success)
![License](https://img.shields.io/badge/License-Educational-blue)

A lightweight Security Information and Event Management (SIEM) system developed using Python and Flask to monitor login activities, detect cyber attacks, visualize security analytics, and assist incident response in real time.

## Overview

Mini SIEM is a lightweight security monitoring platform designed for educational purposes. It collects authentication logs, analyzes login activities, detects multiple attack types, and visualizes security events through an interactive web dashboard.

The project demonstrates how a basic SIEM system performs log collection, attack detection, threat monitoring, reporting, and IP blocking using Python and Flask.

## Project Information

| Item | Details |
|------|---------|
| Project | Mini SIEM Dashboard |
| Language | Python |
| Framework | Flask |
| Frontend | HTML, CSS, Bootstrap, JavaScript |
| Charts | Chart.js |
| Log Storage | JSON |
| Version | v1.0 |
| Purpose | Educational Security Monitoring System |

## Features

- Real-time login monitoring
- Security event logging
- Interactive analytics dashboard
- Attack detection engine
- Threat history management
- IP blocking
- Threat resolution workflow
- CSV report export
- Threat report export
- Login activity analytics
- Responsive Bootstrap UI

## Attack Detection

The system detects multiple attack types.

- Brute Force Attack
- Credential Stuffing
- Username Enumeration
- Mixed Attack

## Dashboard Features

### Overview

- Total Events
- Successful Logins
- Failed Logins
- Login Success vs Failure Pie Chart
- Security Events Bar Chart

### Analytics

- Top Targeted Usernames
- Top Source IP Addresses
- Login Attempts Per Day
- Login Attempts Per Hour
- Drill-down Daily → Hourly
- Time Filters
  - Today
  - Last 7 Days
  - Last 30 Days
  - All Time

### Threat Management

- Active Alerts
- Threat Distribution Chart
- Threat History
- Block IP
- Resolve Threat

### Event Logs

- Recent Security Events

## Technologies Used

### Backend
- Python
- Flask

### Frontend
- HTML5
- CSS3
- Bootstrap 5
- JavaScript
- Chart.js

### Data Storage
- JSON

### Python Packages
- Flask
- Requests

## Project Structure

```
Mini-SIEM/
│
├── analyzer/
├── static/
│   ├── css/
│   ├── js/
├── templates/
├── logs/
├── docs/
├── simulations/
├── app.py
├── requirements.txt
└── README.md
```

## Installation

Clone the repository

```bash
git clone https://github.com/Jithendra-ayesh/mini-siem-dashboard.git
```

Open project

```bash
cd mini-siem-dashboard
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run Flask

```bash
python app.py
```

Open

```
http://127.0.0.1:5000
```

## Usage

Normal User Login

```
http://127.0.0.1:5000/login
```

Administrator Dashboard

```
http://127.0.0.1:5000/admin-login
```

Run attack simulator

```bash
python simulations/brute_force_simulator.py
```

## Reports

The system supports

- Security Event Report Export
- Threat Report Export

## Future Improvements

Future work (Phase 2) will extend the Mini SIEM with packet analysis, network traffic monitoring, and advanced threat detection capabilities.

- Packet Analysis
- Network Traffic Monitoring
- Email Alert Notifications
- Machine Learning Based Detection
- Database Integration
- Multi-user Authentication
- Role Based Access Control
- Docker Deployment

## License

This project was developed for academic and educational purposes.

It is intended for learning, research, and demonstration of basic SIEM concepts.

## Screenshots

### Login Pages

<p align="center">
    <img src="screenshots/login.png" width="45%">
    <img src="screenshots/admin-login.png" width="45%">
</p>

---

### Dashboard

<p align="center">
    <img src="screenshots/dashboard-overview.png" width="90%">
</p>

---

### Analytics

<p align="center">
    <img src="screenshots/analytics.png" width="90%">
</p>

---

### Threat Management

<p align="center">
    <img src="screenshots/threats.png" width="90%">
</p>

## Project Status

**Version:** v1.0

✅ Completed

- Log Collection
- Attack Simulation
- Threat Detection
- Dashboard
- Analytics
- Reporting
- IP Blocking