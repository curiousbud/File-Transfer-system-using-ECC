# 🔐 Qubix: Secure File Transfer System Using Elliptic Curve Cryptography (ECC)

## 📋 Project Overview

**Qubix** is an advanced secure file transfer system that leverages **Elliptic Curve Cryptography (ECC)** to provide enterprise-level security for file sharing and storage. This major project demonstrates cutting-edge cryptographic techniques while maintaining user-friendly functionality.

### 🎯 Project Objectives
- Implement secure file transfer using ECC hybrid encryption
- Demonstrate ECC advantages over traditional RSA encryption
- Create a comprehensive friendship-based access control system
- Provide real-time security monitoring and audit trails
- Achieve academic research standards for cryptographic implementation

### 🛠️ Technology Stack
- **Backend**: Django 5.2.4, Python 3.13
- **Cryptography**: `cryptography`, `pycryptodome`, `ecdsa`
- **Database**: SQLite (Development), PostgreSQL (Production)
- **Frontend**: Bootstrap 4, JavaScript
- **Real-time**: Django Channels (Future implementation)

---

## 📅 Implementation Timeline (12 Weeks)

### 🔑 **Week 1-2: ECC Foundation & Key Management** ✅ COMPLETED
**Objective**: Establish the cryptographic foundation with ECC key generation and management

#### Features to Implement:
- [x] ECC key pair generation (P-256, P-384, secp256k1)
- [x] Secure key storage with password-based encryption
- [x] Key rotation mechanism
- [x] Basic ECC utilities and helper functions
- [x] User key management interface

#### Technical Components:
- ✅ `crypto/ecc_manager.py` - Core ECC operations
- ✅ `users/models.py` - ECCKeyPair model
- ✅ `crypto/key_storage.py` - Secure key storage
- ✅ Key generation views and templates

---

### 🔒 **Week 3-4: Hybrid Encryption Implementation** ✅ CURRENT
**Objective**: Implement hybrid encryption (ECC + AES) for file security

#### Features to Implement:
- [ ] ECDH key agreement protocol
- [ ] AES-256 file encryption/decryption
- [ ] ChaCha20 alternative encryption
- [ ] File chunking for large files
- [ ] Encryption metadata management

#### Technical Components:
- `crypto/hybrid_encryption.py` - Main encryption logic
- `crypto/file_handler.py` - File processing utilities
- `blog/models.py` - SecureFile model updates
- Encryption/decryption views

---

### ✍️ **Week 5-6: Digital Signatures & Verification**
**Objective**: Add file integrity and authentication through digital signatures

#### Features to Implement:
- [ ] ECDSA digital signature implementation
- [ ] File integrity verification (SHA-256)
- [ ] Signature verification system
- [ ] Non-repudiation features
- [ ] Audit trail for signature events

#### Technical Components:
- `crypto/digital_signatures.py` - Signature operations
- `security/integrity_checker.py` - File verification
- Signature verification views
- Audit logging system

---

### 🤝 **Week 7-8: Advanced Security & Access Control**
**Objective**: Enhance security with advanced access control and monitoring

#### Features to Implement:
- [ ] Time-based access expiration
- [ ] Multi-level access permissions
- [ ] Real-time threat detection
- [ ] Failed access attempt monitoring
- [ ] Automated key rotation

#### Technical Components:
- `security/threat_detection.py` - Security monitoring
- `security/access_control.py` - Permission management
- Advanced friendship models
- Security dashboard

---

### 📊 **Week 9-10: Performance Optimization & Analytics**
**Objective**: Optimize performance and add comprehensive analytics

#### Features to Implement:
- [ ] Performance benchmarking (ECC vs RSA)
- [ ] Caching mechanisms
- [ ] Background task processing
- [ ] Real-time analytics dashboard
- [ ] Security metrics collection

#### Technical Components:
- `analytics/performance_monitor.py` - Performance tracking
- `analytics/security_dashboard.py` - Dashboard views
- Celery integration for background tasks
- Performance optimization utilities

---

### 📚 **Week 11-12: Documentation & Research Analysis**
**Objective**: Complete academic documentation and research analysis

#### Features to Implement:
- [ ] Comprehensive research paper
- [ ] Security analysis documentation
- [ ] Performance comparison studies
- [ ] Implementation guide
- [ ] API documentation

#### Deliverables:
- Research paper (20+ pages)
- Security analysis report
- Performance benchmarking results
- Complete API documentation

---

## ✅ Current Progress Checklist

### 🔑 Week 1-2: ECC Foundation & Key Management

#### Core Implementation Tasks:
- [x] **Project Structure Setup**
  - [x] Create crypto utilities directory
  - [x] Setup ECC libraries installation
  - [x] Basic project documentation

- [x] **ECC Key Management System**
  - [x] Create ECCKeyPair model with encryption support
  - [x] Implement key pair generation (P-256, P-384, secp256k1)
  - [x] Secure private key storage with PBKDF2 + AES-256-CTR encryption
  - [x] Key rotation mechanism with versioning

- [x] **User Interface Components**
  - [x] Key generation views
  - [x] Key management dashboard
  - [x] Key rotation interface
  - [x] Navigation integration

- [x] **Database & Models**
  - [x] ECCKeyPair model implementation
  - [x] KeyRotationLog for audit trail
  - [x] Database migrations
  - [x] Friendship system integration

#### Files Created/Modified:
- [x] `qubix/crypto/__init__.py`
- [x] `qubix/crypto/ecc_manager.py`
- [x] `qubix/crypto/key_storage.py`
- [x] `qubix/crypto/curves.py`
- [x] `qubix/users/models.py` (Added ECCKeyPair & KeyRotationLog)
- [x] `qubix/users/views.py` (Added key management views)
- [x] `qubix/users/templates/users/key_management.html`
- [x] `qubix/blog/templates/blog/base.html` (Navigation updates)

---

## 🏗️ Technical Architecture

### Database Schema Extensions

```sql
-- ECC Key Management
CREATE TABLE users_ecckeypaair (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES auth_user(id),
    private_key_encrypted TEXT NOT NULL,
    public_key TEXT NOT NULL,
    curve_name VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    key_version INTEGER DEFAULT 1
);

-- Secure File Storage
CREATE TABLE blog_securefile (
    id SERIAL PRIMARY KEY,
    original_name VARCHAR(255),
    encrypted_file_path VARCHAR(500),
    encryption_algorithm VARCHAR(20),
    digital_signature TEXT,
    file_hash VARCHAR(64),
    created_by_id INTEGER REFERENCES auth_user(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- File Access Control
CREATE TABLE blog_fileaccess (
    id SERIAL PRIMARY KEY,
    file_id INTEGER REFERENCES blog_securefile(id),
    user_id INTEGER REFERENCES auth_user(id),
    encrypted_symmetric_key TEXT,
    access_granted_at TIMESTAMP DEFAULT NOW(),
    access_expires_at TIMESTAMP,
    access_count INTEGER DEFAULT 0
);
```

### Security Requirements

1. **Cryptographic Standards**
   - NIST P-256, P-384 curves for government compliance
   - Curve25519 for high-performance applications
   - AES-256-GCM for symmetric encryption
   - SHA-256 for hashing and integrity

2. **Key Management**
   - PBKDF2 with 100,000 iterations for key derivation
   - Secure random number generation
   - Key rotation every 90 days
   - Hardware security module (HSM) support (future)

3. **Access Control**
   - Zero-knowledge architecture
   - Time-based access expiration
   - Multi-factor authentication integration
   - Comprehensive audit logging

---

## 📖 Research Components

### Academic Contributions

1. **Performance Analysis**
   - ECC vs RSA performance comparison
   - Different curve performance analysis
   - Scalability testing with large files
   - Memory usage optimization

2. **Security Analysis**
   - Threat modeling and risk assessment
   - Cryptographic protocol verification
   - Side-channel attack resistance
   - Quantum resistance considerations

3. **Implementation Innovation**
   - Hybrid encryption optimization
   - Real-time key exchange protocols
   - Efficient large file handling
   - Cross-platform compatibility

---

## 🚀 Getting Started

### Prerequisites
```bash
Python 3.13+
Django 5.2.4
Virtual environment (recommended)
```

### Installation
```bash
# Clone the repository
git clone https://github.com/curiousbud/File-Transfer-system-using-ECC.git
cd File-Transfer-system-using-ECC

# Activate virtual environment
.\major\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Install cryptographic libraries
pip install cryptography pycryptodome ecdsa

# Run migrations
python qubix/manage.py makemigrations
python qubix/manage.py migrate

# Start development server
python qubix/manage.py runserver
```

---

## 📝 Current Status

**Current Phase**: Week 3-4 - Hybrid Encryption Implementation
**Next Milestone**: Implement secure file encryption using ECC + AES hybrid approach
**Overall Progress**: 40% Complete

### Recent Achievements
- ✅ **Week 1-2 COMPLETED**: ECC Foundation & Key Management
- ✅ Complete ECC key pair generation with P-256, P-384, secp256k1 curves
- ✅ Secure key storage with PBKDF2 + AES-256-CTR encryption
- ✅ Key rotation mechanism with audit logging
- ✅ Professional key management dashboard
- ✅ Friendship-based access control system
- ✅ Database models and migrations

### Upcoming Tasks - Week 3-4
- 🔄 Implement hybrid encryption for file security
- 🔄 Create SecureFile model for encrypted file storage
- 🔄 Build file encryption/decryption views
- 🔄 Add file chunking for large files

---

## 🤝 Contributing

This is an academic project demonstrating advanced cryptographic implementations. Contributions should focus on:
- Security improvements
- Performance optimizations
- Documentation enhancements
- Test coverage improvements

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📧 Contact

**Project Author**: Akare
**Institution**: [Your University Name]
**Course**: Major Project - Cryptography & Network Security
**Academic Year**: 2024-2025

---

*Last Updated: July 26, 2025*
*Project Status: Active Development - Week 1-2*
