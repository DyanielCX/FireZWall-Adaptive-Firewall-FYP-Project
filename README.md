# 🔥 FireZWall - Adaptive Firewall Management System

### A modern web-based firewall management system with integrated honeypot monitoring

![python_vers](https://img.shields.io/badge/Python->=3.13.7-blue)
![node_vers](https://img.shields.io/badge/node->=20.19.5-blue)
![npm_vers](https://img.shields.io/badge/npm->=9.2.0-blue)
![platform](https://img.shields.io/badge/Platform-Kali_Linux-yellow)
![status](https://img.shields.io/badge/Status-updating-green)
<a href="https://www.linkedin.com/in/dyaniel-ching-chee-xiong-1ba97b228/">
    <img alt="Twitter: FranckAbgrall" src="https://img.shields.io/badge/LinkedIn-0077B5" target="_blank" />
  </a>


[About](#-about) • [Prerequisites](#-prerequisites) • [Installation](#-installation) • [Tech Stack](#%EF%B8%8F-tech-stack) • [Usage](#-usage) • [Features](#-features) • [Screenshots](#-screenshots)


## 📖 About

FireZWall is an **Adaptive Firewall Management System** developed as a Final Year Project (FYP). It provides a modern web interface for managing UFW (Uncomplicated Firewall) rules with integrated Cowrie honeypot monitoring capabilities for educational and security research purposes. FireZWall also provides the API service for automating the firewall management in order to be integrated with other security system like SIEM & CTI.

---

## 📋 Prerequisites

Before installation, ensure you have:

- **Operating System**: Debian-based Linux
- **Python**: 3.13.7 or higher
- **Node.js**: 20.19.5 or higher
- **npm**: 9.2.0 or higher
- **UFW**: Installed and configured
- **Cowrie**: Installed (Included in github repo)
- **sudo privileges**: Required for UFW operations


## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/DyanielCX/FireZWall-Adaptive-Firewall-FYP-Project.git
cd FireZWall-Adaptive-Firewall-FYP-Project
```

### 2. Virtual Environment & Dependencies Setup

```bash
# Update apt
sudo apt update

# Create virtual environment
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

```

### 3. Cowrie Environment Setup

```bash
# Navigate to cowrie folder
cd cowrie

# Setup cowrie environment 
export SETUPTOOLS_SCM_PRETEND_VERSION_FOR_COWRIE=2.8.1
python -m pip install -e .

```

### 4. UFW Configuration

```bash
# Enable UFW
sudo ufw enable

# Allow port 5000 for FireZWall (CRITICAL - DO NOT SKIP)
sudo ufw allow 5000/tcp

# Allow port 22 & 23 for Cowrie (CRITICAL - DO NOT SKIP)
sudo ufw allow 22/tcp
sudo ufw allow 23/tcp

# Verify UFW is running
sudo ufw status
```

### 5. Launch the FireZWall Server

```bash
# Back to FireZWall directory
cd ~/<cloned_dir>/FireZWall-Adaptive-Firewall-FYP-Project

# Open FireZWall.py
sudo nano FireZWall.py

# Change `SERVER_IP`
SERVER_IP = '<your-machine-ip-addr>'

# Save the file
(ctrl + X -> y -> enter)
```

### 6. Launch the FireZWall Server

```bash
# Run the flask server
python FireZWall.py
```
The server will run on `https://localhost:5000`

---

## 🛠️ Tech Stack

### Frontend
- React
- Vite
- Tailwind CSS

### Backend
- Flask
- Flask-RESTful
- SQLAlchemy

### Security & System
- OAuth 2.0
- Werkzeug
- UFW
- Cowrie

### Database
- SQLite

---

## 💻 Usage

### Default Admin Account
| Role          | Username   | Password    |
|---------------|------------|-------------|
| Default admin | admin      | @dM1np4ss   |

> ⚠️ **Security Warning**: Change default admin account passwords immediately in production!

### Accessing the Application

1. Open your browser and navigate to `https://localhost:5000`
2. Login with default admin account
3. Explore all the features

---

## ✨ Features

### Firewall Management
- View all active UFW firewall rules in real-time
- Add new firewall rules with port/protocol validation
- Delete existing rules with safety protections
- Common service port autocomplete

### User Management (Admin only)
- Complete user CRUD operations
- Role-based access control (Admin, Developer, CyberSec, Regular User)
- Password strength validation

### Honeypot Monitoring
- Real-time SSH/Telnet attack detection via Cowrie
- Attack pattern visualization
- UTC+8 timezone support for Malaysia region

### System Logs
- Comprehensive audit trail
- Role-based log filtering
- Action tracking with timestamps
- User activity monitoring

### Lab Mode
- Safe practice environment for learning
- Interactive firewall management tutorials
- API usage demonstrations
- Step-by-step guided exercises

### Authentication & Security
- OAuth 2.0 authentication
- Automatic token refresh mechanism
- Secure cookie-based token storage

### Available API Endpoint
- Flask-RESTful API framework
- Designed for automation firewall management
- More details can view API documentation `https://localhost:5000/api-docs`

---

## 📸 Screenshots

### Landing Page
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/aa761407-a3d2-40ae-8e00-c2457d87615e" />

### API Documnetation
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/73991ea2-568a-4177-9675-20af5b2c58b4" />

### Login Page
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/9929135b-199a-483d-8fd4-795ca6bb02c7" />

### Dashboard
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/e765d93d-654f-4bad-8758-a6946117a046" />

### Firewall Rules Management
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/560671ed-98d4-4b17-8832-149aeeb2e969" />

### User Management
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/a30c94ab-06ef-43a0-90df-be5938d3cd03" />

### Honeypot Reports
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/8e86da4c-ecac-48d0-b48e-b5f7b899fcde" />

### System Logs
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/6df74fbd-a6e0-4474-afd2-21bd02150d4f" />

### Lab Mode
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/794c9974-c8e0-4582-b7e5-9ca1a80554ca" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/55e69316-0595-475f-a816-1a13b89836b4" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/5c4b330c-efdf-4731-a27c-55156ed7aab7" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/3310013f-02c2-4cca-9b47-2da672f4553e" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/f414a32e-d267-43ca-a74a-9a4eb383afa2" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/52704688-814b-4f4d-a5eb-78ef4b3845d7" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/6ba7dd8e-b400-408f-9881-7990c3e43bf8" />

---

## 👨‍💻 Author

**Dyaniel Ching Chee Xiong**
- GitHub: [@DyanielCX](https://github.com/DyanielCX)
- Email: dyanielcx@gmail.com

**Project Supervisor**: Ms. Noris Ismail  
**Institution**: Asia Pacific University  
**Development Year**: 2025-2026

---

## 🙏 Acknowledgments

- **OWASP ZAP** - Design inspiration for security-focused UI
- **Cowrie Project** - SSH/Telnet honeypot integration
- **UFW** - Simple and effective firewall management
- **React Community** - Excellent documentation and support
- **Flask Community** - Robust web framework

---


**⭐ If you find this project useful, please consider giving it a star! ⭐**

Made for cybersecurity education purpose

