<div id="badges">
  <a href="https://www.linkedin.com/in/adrian-korwel-83226a300/">
    <img src="https://img.shields.io/badge/LinkedIn-blue?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn Badge"/>
  </a>
</div>

# Secure Encryption & Azure Key Vault Integration

## Releases
All versions of the programs are available in the **[Releases](https://github.com/adriank31/HSM_AES256/releases)** section under the following **tags:**
- 🏷 **v1** - Password Hashing & HMAC Authentication
- 🏷 **v2** - Secure Key Derivation & AES Encryption
- 🏷 **v3** - Azure Key Vault Integration & HSM Simulation

---

## Project Overview
This project provides **secure encryption, key wrapping, and Azure Key Vault integration** using **OpenSSL** and **cURL**. It includes:
- **PBKDF2-HMAC-SHA256** for **password hashing**
- **AES-256-GCM encryption** for **secure message encryption**
- **Azure Key Vault integration** for **cloud-based key management**
- **HSM simulation** for **secure key handling**

---

## Installation Guide

### **Step 1: Install Required Dependencies**

#### **For Linux/macOS**
```bash
sudo apt update && sudo apt install -y openssl libssl-dev curl jq azure-cli
brew install openssl curl jq azure-cli  # macOS (Homebrew)
```

#### **For Windows**
1. **Download and install OpenSSL**
2. **Download and install Azure CLI**
3. **Install cURL & jq using Chocolatey:**
```powershell
choco install curl jq
```

---

## Program Versions & Usage

### **v1: Secure Key Derivation & AES Encryption**
#### **Features:**
- PBKDF2-HMAC-SHA256 derives keys from passwords
- AES-256-GCM provides authenticated encryption
- Random IV generation with OpenSSL

#### **To Compile and Run:**
```bash
gcc PBKDF2_AES256.c -o PBKDF2_AES256 -lcrypto
./PBKDF2_AES256
```

---

### **v2: AES Encryption & HSM Simulation**
#### **Features:**
- Encrypted DEK/KEK inside Database(HSM)
- Encrypts user-provided-message using AES-256-GCM with unencrypted DEK
- Random IV generation with OpenSSL

#### **To Compile and Run:**
```bash
gcc HSM_AES256.c -o HSM_AES256 -lcrypto
./HSM_AES256
```

---

### **v3: Azure Key Vault Integration & HSM Simulation**
#### **Features:**
- Generates KEK & DEK inside a simulated HSM
- Encrypts & wraps the DEK using KEK
- Fetches KEK from Azure Key Vault
- Encrypts messages securely with AES-256-GCM

#### **To Compile and Run:**
```bash
gcc HSM_AZURE_AES256.c -o HSM_AZURE_AES256 -lcrypto -lcurl
./HSM_AZURE_AES256
```

#### **Set Environment Variables:**
```bash
export AZURE_KEY_VAULT="https://yourvault.vault.azure.net"
export AZURE_KEY_NAME="KEK"
```

---

## Example Usage

#### **Run the Program:**
```bash
./azure_encrypt
```

#### **User Input:**
```plaintext
Enter message to encrypt: Secure Encryption Works!
```

#### **Output:**
```plaintext
Generated IV: f8d3a9e2c5a4
Encrypted Message: 7d9a1b04d87a34e2bcf9
Authentication Tag: 3e5a9f1e8b73
```

---

## Troubleshooting

#### **Azure Key Vault Permission Issues?**
```bash
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv)
```

#### **Invalid Azure Access Token**
```bash
az logout && az login
```

#### **OpenSSL Errors**
```bash
openssl version
```

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## Notes
Check out my uploaded notes for an in-depth explanation of encryption/decryption with code analysis.
