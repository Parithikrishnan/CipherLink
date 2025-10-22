# Cipher Link 🔐

## Overview ⚙️
**Cipher Link** is a secure local network chat and file-sharing application built entirely in Python. It enables encrypted messaging and authenticated file transfers within a local network using **socket programming**. Every transferred file is verified using its **hash value** to ensure authenticity and integrity.  

The application also implements **tree and multigraph logging** to track message delivery and file transfer events in a structured format, providing a clear record of all communication activities.

---

## Features ✨

- **💬 Secure Local Chat:** Exchange messages in real-time within a local network.  
- **📁 File Sharing with Integrity Check:**  
  - Transfer files across the network.  
  - Automatically compute and verify SHA hash values to ensure file authenticity.  
- **🛡️ Authentication & Security:** Prevents tampering and ensures messages/files come from verified sources.  
- **🌳 Tree Logging:**  
  - Maintains a log of who sent which message or file.  
  - Provides hierarchical and network-graph views of communication history.  
- **🖥️ Pure Python Implementation:** Built entirely using Python’s standard libraries, including **socket** programming for network communication.  

---

## Technical Architecture 🛠️

### 1. Networking
- **Socket Programming:** Enables TCP/UDP-based connections for secure messaging and file transfer across a LAN.  
- **Client-Server Model:** Supports multiple clients connected to a server with concurrent communication.

### 2. Security
- **SHA Hash Verification:**  
  - Every file is hashed before sending.  
  - Recipient verifies the hash to confirm file authenticity.  
- **Message Integrity:** Ensures messages are received unaltered.  

### 3. Logging
- **Tree Structure:** Logs message flow hierarchically for easier tracking.  
- **Multigraph Structure:** Captures complex relationships between multiple participants in the network, visualizing who sent what to whom.  

### 4. Concurrency
- Supports multiple clients simultaneously, ensuring smooth communication and file transfer operations.  

---

## Getting Started 🚀

### Prerequisites
- Python 3.10+  
- Libraries: `hashlib`, `socket`, `threading`, `networkx` (for multigraph/tree logging visualization)

### Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/cipher-link.git

python -m venv venv

source venv/bin/activate

python -m pip install -r requirements.txt

python main.py
