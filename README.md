# Multi Party Domain Cryptosystem (MPDC-I)

The Multi Party Domain Cryptosystem protocol

## Introduction

MPDC-I (Multi Party Domain Cryptosystem - Interior Protocol) is a multi‐party key exchange and network security system. It distributes the security of a key exchange between a server and a client across multiple devices. This design leverages the contribution of network agents—trusted devices that each inject a portion of pseudo‐random material into the key exchange process—ensuring that no single entity controls the entire shared-secret derivation.

On an interior network, the server and client establish a shared secret with each authenticated agent using an asymmetric key exchange. The resulting shared-secret, retained for the lifetime of the device's certificate, is used to generate a unique key-stream to encrypt small chunks of pseudo‐random data called "key fragments". These fragments are subsequently combined and hashed to derive the primary session keys that secure the encrypted tunnel between the server and client.

This approach means that any attack involving impersonation or man‐in‐the‐middle tactics would have to simultaneously compromise multiple, independently authenticated network devices. Unlike other schemes that rely solely on expensive classical asymmetric cryptography, MPDC-I utilizes a hybrid asymmetric/symmetric post‐quantum secure design. This provides not only robust security but also scalability and computational efficiency, making it suitable for wide-scale adoption.

[View full documentation online](https://qrcs-corp.github.io/MPDC/)

## Architecture Overview

MPDC-I operates with five key device types, each fulfilling a distinct role within the security ecosystem:

### Client

**Role:**  
An end-user network device that initiates secure communication with the MPDC-enabled Application Server.

**Functions:**
- Generates its own certificate and stores the secret signing key.
- Has its certificate signed by the RDS (Root Domain Security server), either directly or by proxy through the DLA.
- Exchanges master fragment keys (mfk) with Agents and MAS servers, which are used to encrypt key fragments.
- Combines key fragments received from Agents with the MAS fragment key to derive secure session keys.
- Encrypts and decrypts messages using the session keys through a duplexed, encrypted, and authenticated tunnel.

### MAS (MPDC Application Server)

**Role:**  
Acts as the central application server managing secure communications with Clients.

**Functions:**
- Generates its own certificate and stores the secret signing key.
- Has its certificate signed by the RDS, directly or via the DLA.
- Validates Client certificates against the RDS root certificate.
- Communicates with Agents to obtain key fragments.
- Derives session keys used to securely interact with Clients.
- Encrypts and decrypts messages over a duplexed, secure tunnel.

### Agent

**Role:**  
A trusted network device that injects additional entropy into the key exchange process.

**Functions:**
- Generates its own certificate and stores its secret signing key.
- Has its certificate signed by the RDS, either directly or via the DLA.
- Generates key fragments (providing pseudo‐random entropy) for session key derivation.
- Securely transmits key fragments to both the MAS and Clients.
- Enhances the overall security of session keys through independent cryptographic processes.

### DLA (Domain List Agent)

**Role:**  
Manages device registration and certificate validation within the network.

**Functions:**
- Generates its own certificate and stores the secret signing key.
- Has its certificate signed by the RDS.
- Validates device certificates using the RDS certificate.
- Maintains a master list of trusted devices (network topology).
- Distributes certificates and topology updates.
- Manages certificate revocation and device resignation.
- Handles topological queries from network devices.

### RDS (Root Domain Security Server)

**Role:**  
Serves as the root certificate authority (trust anchor) for the network.

**Functions:**
- Generates and manages the root certificate.
- Signs device certificates to authenticate identity and trust.
- May operate as a certificate signing proxy in conjunction with the DLA.

## MPDC-I Protocol Overview

MPDC-I distributes the key exchange security across multiple devices:

- **Key Fragment Exchange:** Each Agent on the network, authenticated by the RDS, contributes a unique key fragment. These fragments are generated using computationally inexpensive symmetric cryptography.
- **Session Key Derivation:** The MAS and Client combine key fragments from all participating Agents with a MAS-specific fragment key. This combination is hashed to derive the primary session keys used to encrypt the communication tunnel.
- **Security Benefits:** An adversary must impersonate multiple devices simultaneously to break the session keys, making man-in-the-middle attacks practically infeasible.
- **Hybrid Cryptography:** MPDC-I employs a post-quantum secure hybrid model combining asymmetric and symmetric cryptography, achieving both high security and efficient performance.

## MPDC Example Configuration

The following steps outline a typical configuration and network initialization process:

- **RDS Initialization:**
  - Log in to the RDS server and issue the `enable` command.
  - Configure your user name, password, device name, IP address, and network name.
  - Switch to config mode, then certificate mode.
  - Generate a root certificate with the command:  
    `generate(days-valid)` (specify the certificate validity period in days).

- **DLA Initialization:**
  - Log in to the DLA server and issue the `enable` command.
  - When prompted, supply the path to the root certificate generated by the RDS.
  - Switch to certificate mode and generate the DLA certificate.

- **RDS Certificate Signing:**
  - On the RDS, switch to certificate mode and sign the DLA's certificate using:  
    `sign(certificate-path)` (where *certificate-path* is the file path to the DLA certificate).
  - Transfer the signed certificate back to the DLA either manually (a server restart may be required) or using the import command in certificate mode.

- **Device Initialization (Agent, MAS, Client):**
  - For each device (Agent, MAS, and Client), generate a certificate and corresponding key-pair.
  - Get each certificate signed by the RDS directly or via the DLA.
  - Register each device with the DLA, which validates the certificate and updates the network topology.

- **MAS and Agent Integration:**
  - On the MAS, join the network by contacting the DLA and obtaining a list of available Agents.
  - Enable the IP service on the MAS.
  - On each Agent, enable the IP service and register with the DLA using:  
    `register(dla-ip-address)`.

- **Client Integration:**
  - On each Client, enable the IP service and register with the DLA.
  - Exchange certificates and master fragment keys with Agents and the MAS.
  - In server mode, use the command `connect(mas-ip-address)` to establish an encrypted tunnel with a MAS.

## File Description

The MPDC library is modular and organized as follows:

- **mpdc.h:** Contains the primary MPDC library API, including constants, structures, and functions used by all servers and clients.
- **server.h:** Contains common server functions for managing configuration, state, certificates, logging, and topology.
- **network.h:** Provides secure communication protocols, key exchanges, and certificate management routines.
- **topology.h:** Manages the network topology, including node registration, serialization, and updates.
- **trust.h:** Handles trust metrics for network devices including serialization and deserialization of trust structures.
- **agent.h:** Implements the Agent security server functionality.
- **client.h:** Implements the MPDC Client functionality.
- **dla.h:** Implements the Domain List Agent server functionality.
- **mas.h:** Implements the MPDC Application Server functionality.
- **rds.h:** Implements the Root Domain Security server functionality.

## Getting Started

To use the MPDC library:

- Include the necessary header files in your project (for example, `server.h`, `network.h`, `topology.h`, `trust.h`, `rds.h`).
- Initialize the appropriate server type (Client, MAS, Agent, DLA, or RDS) via the provided API functions.
- Follow the configuration steps detailed above to properly set up your secure MPDC network.

### Cryptographic Dependencies

MPDC-I uses the QSC cryptographic library: [The QSC Library](https://github.com/QRCS-CORP/QSC).  
*QRCS-PL private License. See license file for details. All rights reserved by QRCS Corporation, copyrighted and patents pending.*


## License

QRCS-PL private License. See license file for details.  
Software is copyrighted and MPDC is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
All rights reserved by QRCS Corp. 2025.
