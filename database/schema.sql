CREATE TABLE admin_users (

    id INT PRIMARY KEY AUTO_INCREMENT,

    username VARCHAR(100) UNIQUE,

    password VARCHAR(255),

    role VARCHAR(50),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

CREATE TABLE files (

    id INT PRIMARY KEY AUTO_INCREMENT,

    file_name VARCHAR(255),

    file_path TEXT,

    hash_value TEXT,

    current_hash TEXT,

    status VARCHAR(50),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

CREATE TABLE alerts (

    id INT PRIMARY KEY AUTO_INCREMENT,

    file_id INT,

    attack_type VARCHAR(100),

    attacker_ip VARCHAR(100),

    severity VARCHAR(50),

    message TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

CREATE TABLE logs (

    id INT PRIMARY KEY AUTO_INCREMENT,

    activity TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

CREATE TABLE reports (

    id INT PRIMARY KEY AUTO_INCREMENT,

    report_name VARCHAR(255),

    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

CREATE TABLE blocked_ips (

    id INT PRIMARY KEY AUTO_INCREMENT,

    ip_address VARCHAR(100),

    reason TEXT,

    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);