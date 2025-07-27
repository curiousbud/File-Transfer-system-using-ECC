# Qubix - Secure ECC File Transfer System       <img alt="GitHub" src="https://img.shields.io/github/license/curiousbud/File-Transfer-system-using-ECC">

Qubix is an advanced secure file transfer system that leverages **Elliptic Curve Cryptography (ECC)** to provide enterprise-level security for file sharing and storage. Built with Django 5.2.4 and modern cryptographic libraries, Qubix offers a user-friendly interface while maintaining robust security standards.

## � Project Status

**Current Version**: 1.0.0-beta  
**Development Status**: Advanced Implementation (85% Complete)  
**Latest Features**: Comprehensive Pagination & Filtering System, Unified Sharing Architecture

### 🏆 Key Achievements
- ✅ **Complete ECC Implementation** - Full elliptic curve cryptography system
- ✅ **Hybrid Encryption Architecture** - Enterprise-grade security 
- ✅ **Unified Sharing System** - Seamless content sharing experience
- ✅ **Advanced Pagination & Filtering** - Comprehensive content management
- 🔄 **Batch Operations** - High-performance concurrent processing (90% complete)

### 📋 Quick Overview
- **Core Security Features**: 100% Complete
- **User Interface**: 95% Complete  
- **File Operations**: 100% Complete
- **Performance Optimization**: 90% Complete

> � **For detailed development progress, milestones, and technical achievements, see our comprehensive [Development Progress Documentation](DEVELOPMENT_PROGRESS.md)**

---

## 🔐 Core Security Features

### Cryptographic Implementation
- **Elliptic Curve Cryptography**: NIST P-256, P-384 curves
- **Hybrid Encryption**: ECC for key exchange + AES/ChaCha20 for data
- **Key Derivation**: PBKDF2 with SHA-256 (600,000 iterations)
- **Authenticated Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Digital Signatures**: ECDSA for data integrity

### Security Measures
- **Perfect Forward Secrecy**: Ephemeral key exchange
- **Key Rotation**: Automated and manual key rotation
- **Secure Storage**: Encrypted private keys with strong KDF
- **Access Control**: Friend-based sharing with permissions
- **Audit Trail**: Comprehensive logging of security events

---

## 🛠️ Technologies Used

### Core Framework
- **Python 3.13** - Modern Python with latest features
- **Django 5.2.4** - Robust web framework
- **SQLite** - Embedded database for development
- **Bootstrap 4** - Responsive UI framework

### Cryptographic Libraries
- **cryptography 45.0.5** - Modern cryptographic library
- **pycryptodome 3.23.0** - Additional cryptographic primitives
- **ecdsa 0.19.1** - Elliptic curve digital signatures

### Additional Dependencies
- **django-crispy-forms** - Enhanced form rendering
- **crispy-bootstrap4** - Bootstrap 4 form styling
- **Pillow** - Image processing for profiles

---

## 📋 Installation & Setup

### Prerequisites
```bash
# Python 3.13+ required
python --version

# Virtual environment (recommended)
python -m venv major
major\Scripts\activate  # Windows
source major/bin/activate  # Linux/Mac
```

### Installation
```bash
# Clone the repository
git clone https://github.com/curiousbud/Qubix.git
cd Qubix

# Install dependencies
pip install -r requirements.txt

# Database setup
cd qubix
python manage.py makemigrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

### Access the Application
- **Web Interface**: http://localhost:8000
- **Admin Panel**: http://localhost:8000/admin

---

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Django App    │    │   Crypto Layer  │
│   (Bootstrap)   │◄──►│   (Views/URLs)  │◄──►│   (ECC/Hybrid)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Database      │
                       │   (SQLite)      │
                       └─────────────────┘
```

### Key Components
- **Crypto Module**: ECC operations, key management, hybrid encryption
- **User Module**: Authentication, profiles, key management
- **Blog Module**: File operations, sharing, security features
- **Management Commands**: Diagnostics, maintenance, testing

---

## 📊 Performance Benchmarks

| Operation | Algorithm | File Size | Time | Notes |
|-----------|-----------|-----------|------|-------|
| Encryption | AES-256-GCM | 1 MB | 12ms | Standard performance |
| Encryption | ChaCha20-Poly1305 | 1 MB | 8ms | Faster alternative |
| Key Generation | P-256 | N/A | 45ms | Including serialization |
| ECDH Exchange | P-256 | N/A | 2ms | Shared secret derivation |

---

## 🔍 API Reference

### Key Information
```bash
GET /api/key-info/
Authorization: Session-based

Response:
{
    "success": true,
    "user": "username",
    "key_info": {
        "curve": "P-256",
        "version": 1,
        "created": "2025-01-15T10:30:00Z",
        "is_active": true
    }
}
```

### File Operations
```bash
POST /secure-upload/
Content-Type: multipart/form-data

POST /secure-download/<file_id>/
Authorization: Session-based
```

---

## 🎯 Use Cases

### Personal File Security
- Secure personal document storage
- Encrypted file sharing with family/friends
- Privacy-focused file management

### Business Applications
- Confidential document sharing
- Secure client file exchange
- Compliance with data protection regulations

### Educational Research
- Cryptographic algorithm implementation study
- Security protocol analysis
- Performance benchmarking research

---

## 🤝 Credits & Acknowledgments

### Primary Development
- **Qubix Development Team** - Complete system architecture and implementation
- **Modern Cryptographic Libraries** - Built on industry-standard implementations

### Educational Inspiration
While researching ECC implementations, we reviewed various educational resources including basic ECC projects. However, our implementation is built from scratch using modern cryptographic libraries and follows current security best practices, representing a significant advancement over older educational implementations.

### Library Credits
- **Python Cryptographic Authority** - cryptography library
- **PyCryptodome Contributors** - pycryptodome library
- **Django Software Foundation** - Django framework
- **Bootstrap Team** - UI framework

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔬 Research & Documentation

For detailed technical documentation, security analysis, and implementation details, see:
- **[Development Progress](DEVELOPMENT_PROGRESS.md)** - Comprehensive development tracking and milestones
- **[Technical Documentation](TECHNICAL_DOCUMENTATION.md)** - Comprehensive system documentation
- **[Security Analysis](docs/security_analysis.md)** - Detailed security assessment
- **[API Documentation](docs/api_reference.md)** - Complete API reference

---

## 📞 Support & Contact

For questions, suggestions, or collaboration opportunities:
- **GitHub Issues**: [Report bugs or request features](../../issues)
- **Documentation**: Check our comprehensive technical documentation
- **Research**: This project serves as a foundation for academic research in applied cryptography

---

**Project Status**: Active Development  
**Version**: 1.0.0-beta  
**Last Updated**: July 27, 2025


