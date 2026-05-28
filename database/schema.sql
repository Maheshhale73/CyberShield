CREATE DATABASE IF NOT EXISTS fim_system;

USE fim_system;

-- =====================================================
-- ADMIN USERS
-- =====================================================

CREATE TABLE admin_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE,
    password VARCHAR(255),
    role VARCHAR(50),
    last_login_ip VARCHAR(100),
    device_info VARCHAR(255),
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- LOGS
-- =====================================================

CREATE TABLE logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    activity TEXT,
    ip_address VARCHAR(100),
    created_at DATETIME
);

-- =====================================================
-- ALERTS
-- =====================================================

CREATE TABLE alerts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    file_id INT NULL,
    attack_type VARCHAR(255),
    attacker_ip VARCHAR(100),
    severity VARCHAR(50),
    message TEXT,
    status VARCHAR(50) DEFAULT 'Open',
    created_at DATETIME
);

-- =====================================================
-- FILES
-- =====================================================

CREATE TABLE files (
    id INT PRIMARY KEY AUTO_INCREMENT,
    file_name VARCHAR(255),
    file_path TEXT,
    hash_value TEXT,
    current_hash TEXT,
    status VARCHAR(50),
    uploaded_at DATETIME
);

-- =====================================================
-- REPORTS
-- =====================================================

CREATE TABLE reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    alert_id INT,
    status VARCHAR(50),
    details LONGTEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- BLOCKED IPS
-- =====================================================

CREATE TABLE blocked_ips (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(100),
    reason TEXT,
    blocked_at DATETIME
);

-- =====================================================
-- SUSPICIOUS IPS
-- =====================================================

CREATE TABLE suspicious_ips (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(100),
    failed_attempts INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);