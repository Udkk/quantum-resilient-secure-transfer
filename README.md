🚀 Hybrid Post‑Quantum Secure File Transfer System
📌 Overview
This project implements a secure client–server file transfer system using a hybrid cryptographic approach that combines classical and post‑quantum algorithms. It ensures confidentiality, integrity, authenticity, and replay protection against both modern and future (quantum) threats.

The system integrates:

ECDH + Kyber (PQC) for key exchange

AES‑256‑GCM for encryption

Dilithium for digital signatures

Together, these make it a research‑grade secure communication model.

🎯 Features
🔐 Hybrid Key Exchange

Combines ECDH (Elliptic Curve Diffie‑Hellman) + Kyber KEM

Secure against classical and quantum attacks

🔑 Secure Key Derivation

HKDF derives strong AES session keys

🛡️ Authenticated Encryption

AES‑256 in GCM mode (confidentiality + integrity)

✍️ Post‑Quantum Digital Signatures

Dilithium ensures authenticity and tamper detection

🚫 Replay Attack Protection

Nonce + timestamp validation

📡 Secure File Transfer

Stream‑based encryption/decryption for large files

🖥️ GUI Support

JavaFX‑based modern UI for client & server

🧱 Modular Architecture

Clean separation of crypto/, network/, and gui/

🏗️ System Architecture
Code
Client (GUI) → Request connection
Server (GUI) → Send ECDH + Kyber Public Keys
Client → Generate ECDH key pair + Kyber encapsulation
Server → Derive Hybrid Shared Secret
Client & Server → HKDF → AES Session Key
File Encryption (AES-GCM)
Sign Metadata (Dilithium)
Secure Transfer
Verify + Decrypt
🔧 Technologies Used
Language: Java (JDK 17+)

Cryptography: AES‑256‑GCM, ECDH, Kyber, Dilithium, HKDF

Libraries: BouncyCastle (PQC support)

Networking: Java Sockets

GUI: JavaFX

Build Tool: IntelliJ / Maven

Version Control: Git

📂 Project Structure
Code
crypto/
 ├── AESUtil.java
 ├── ECDHKeyExchange.java
 ├── KyberKeyExchange.java
 ├── DilithiumKeyExchange.java
 ├── HybridKeyDerivation.java
 ├── HashUtil.java
 └── CryptoProvider.java

network/
 ├── SecureClient.java
 └── SecureServer.java

gui/
 ├── ClientGUI.java
 └── ServerGUI.java

MainClient.java
MainServer.java
README.md
⚙️ Setup Instructions
1️⃣ Prerequisites
Java JDK 17+

IntelliJ IDEA / Eclipse

JavaFX SDK installed

BouncyCastle PQC libraries

2️⃣ Configure JavaFX VM Options
In IntelliJ:

Code
--module-path "C:\javafx-sdk-XX\lib" --add-modules javafx.controls,javafx.fxml
3️⃣ Add BouncyCastle Dependencies
Include:

bcprov

bcpkix

bcutil (if required)

▶️ How to Run
Step 1: Start Server  
Run ServerGUI.java or MainServer.java

Step 2: Start Client  
Run ClientGUI.java or MainClient.java <file_path>

Step 3: Transfer File

Select file in client GUI

Click Send Securely

Server receives and decrypts file

🔐 Security Design
✅ Hybrid Cryptography: ECDH + Kyber → future‑proof

✅ AES‑GCM: Encryption + integrity via authentication tag

✅ Digital Signatures: Dilithium ensures authenticity & tamper detection

✅ Replay Protection: Nonce + timestamp validation

🧪 Testing & Validation
Tampering Test: Modify metadata → ❌ Signature invalid

Replay Attack: Resend old packet → ❌ Rejected

Integrity Test: Modify encrypted file → ❌ GCM tag failure

🚧 Future Enhancements
🌐 TLS‑like protocol layer

☁️ Cloud storage integration

🔑 Key rotation & certificate system

📊 Transfer analytics dashboard

🧠 AI‑based intrusion detection

📈 Use Cases
Secure enterprise file transfer

Government / defense communication

Research in post‑quantum cryptography

Secure cloud storage pipelines

👨‍💻 Author
Udit Kumar  
B.E. Computer Science Engineering
