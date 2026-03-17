________________________________________
🚀 Hybrid Post-Quantum Secure File Transfer System
📌 Overview
This project implements a secure client–server file transfer system using a hybrid cryptographic approach that combines classical and post-quantum algorithms. It ensures confidentiality, integrity, authenticity, and replay protection against modern and future (quantum) threats.
The system integrates ECDH + Kyber (PQC) for key exchange, AES-GCM for encryption, and Dilithium for digital signatures, making it a research-grade secure communication model.
________________________________________
🎯 Features
•	🔐 Hybrid Key Exchange
o	Combines ECDH (Elliptic Curve Diffie-Hellman) + Kyber KEM
o	Secure against both classical and quantum attacks
•	🔑 Secure Key Derivation
o	Uses HKDF to derive strong AES session keys
•	🛡️ Authenticated Encryption
o	AES-256 in GCM mode (confidentiality + integrity)
•	✍️ Post-Quantum Digital Signatures
o	Dilithium ensures authenticity and tamper detection
•	🚫 Replay Attack Protection
o	Nonce + timestamp validation
•	📡 Secure File Transfer
o	Stream-based encryption/decryption for large files
•	🖥️ GUI Support
o	JavaFX-based modern UI for client & server
•	🧱 Modular Architecture
o	Clean separation of:
	crypto/
	network/
	gui/
________________________________________
🏗️ System Architecture
Client (GUI)
   |
   | 1. Request connection
   v
Server (GUI)
   |
   | 2. Send ECDH + Kyber Public Keys
   v
Client
   |
   | 3. Generate:
   |    - ECDH key pair
   |    - Kyber encapsulation
   v
Server
   |
   | 4. Derive Hybrid Shared Secret
   v
Client & Server
   |
   | 5. HKDF → AES Session Key
   |
   | 6. File Encryption (AES-GCM)
   |
   | 7. Sign Metadata (Dilithium)
   |
   | 8. Secure Transfer
   |
   | 9. Verify + Decrypt
________________________________________
🔧 Technologies Used
•	Language: Java
•	Cryptography:
o	AES-256-GCM
o	ECDH
o	Kyber (Post-Quantum KEM)
o	Dilithium (Post-Quantum Signature)
o	HKDF
•	Libraries: BouncyCastle (PQC support)
•	Networking: Java Sockets
•	GUI: JavaFX
•	Build Tool: IntelliJ / Maven (optional)
•	Version Control: Git
________________________________________
📂 Project Structure
├── crypto/
│   ├── AESUtil.java
│   ├── ECDHKeyExchange.java
│   ├── KyberKeyExchange.java
│   ├── DilithiumKeyExchange.java
│   ├── HybridKeyDerivation.java
│   ├── HashUtil.java
│   └── CryptoProvider.java
│
├── network/
│   ├── SecureClient.java
│   └── SecureServer.java
│
├── gui/
│   ├── ClientGUI.java
│   └── ServerGUI.java
│
├── MainClient.java
├── MainServer.java
└── README.md
________________________________________
⚙️ Setup Instructions
1️⃣ Prerequisites
•	Java JDK 17+
•	IntelliJ IDEA / Eclipse
•	JavaFX SDK installed
•	BouncyCastle PQC libraries
________________________________________
2️⃣ Add JavaFX VM Options
In IntelliJ:
--module-path "C:\javafx-sdk-XX\lib" --add-modules javafx.controls,javafx.fxml
________________________________________
3️⃣ Add BouncyCastle Dependencies
Make sure these jars are included:
•	bcprov
•	bcpkix
•	bcutil (if required)
________________________________________
▶️ How to Run
Step 1: Start Server
Run:
ServerGUI.java
or
MainServer.java
________________________________________
Step 2: Start Client
Run:
ClientGUI.java
or
MainClient.java <file_path>
________________________________________
Step 3: Transfer File
•	Select file in client GUI
•	Click Send Securely
•	Server receives and decrypts file
________________________________________
🔐 Security Design
✅ Hybrid Cryptography
•	ECDH → classical security
•	Kyber → quantum-resistant
•	Combined → future-proof
✅ AES-GCM
•	Provides:
o	Encryption
o	Integrity (via authentication tag)
✅ Digital Signatures
•	Dilithium ensures:
o	Sender authenticity
o	Tamper detection
✅ Replay Protection
•	Nonce + timestamp validation prevents reuse attacks
________________________________________
🧪 Testing & Validation
You can test security features:
🔹 Tampering Test
•	Modify metadata/signature → ❌ Signature invalid
🔹 Replay Attack
•	Resend old packet → ❌ Rejected
🔹 Integrity Test
•	Modify encrypted file → ❌ GCM tag failure
________________________________________
🚧 Future Enhancements
•	🌐 TLS-like protocol layer
•	☁️ Cloud storage integration
•	🔑 Key rotation & certificate system
•	📊 Transfer analytics dashboard
•	🧠 AI-based intrusion detection
________________________________________
📈 Use Cases
•	Secure enterprise file transfer
•	Government / defense communication
•	Research in post-quantum cryptography
•	Secure cloud storage pipelines
________________________________________
👨‍💻 Author
Udit Kumar
B.E. Computer Science Engineering
________________________________________

