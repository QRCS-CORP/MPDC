# MPDC-I: Multi Party Domain Cryptosystem (Interior Protocol)

## Introduction

[![Build](https://github.com/QRCS-CORP/MPDC/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/MPDC/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/MPDC/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/MPDC/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/mpdc/badge)](https://www.codefactor.io/repository/github/qrcs-corp/mpdc)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/MPDC/security/policy) 
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/MPDC/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/MPDC/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/MPDC)](https://github.com/QRCS-CORP/MPDC/releases/tag/2025-06-04)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/MPDC.svg)](https://github.com/QRCS-CORP/MPDC/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=ISO/IEC%2011770-5&color=blue)](https://www.iso.org/standard/75295.html)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Financial&color=brightgreen)](#)

**MPDC-I: A Hybrid Post-Quantum Multi‐Party Key Exchange System for Distributed Network Security**

## Overview

MPDC-I (Multi Party Domain Cryptosystem - Interior Protocol) is a multi‐party key exchange and network security system. It distributes the security of a key exchange between a server and a client across multiple devices. This design leverages the contribution of network agents; trusted devices that each inject a portion of pseudo‐random material into the key exchange process, ensuring that no single entity controls the entire shared-secret derivation.

On an interior network, the server and client establish a shared secret with each authenticated agent using an asymmetric key exchange. The resulting shared-secret, retained for the lifetime of the device's certificate, is used to generate a unique key-stream to encrypt small chunks of pseudo‐random data called "key fragments". These fragments are subsequently combined and hashed to derive the primary session keys that secure the encrypted tunnel between the server and client.

This approach means that any attack involving impersonation or man‐in‐the‐middle tactics would have to simultaneously compromise multiple, independently authenticated network devices. Unlike other schemes that rely solely on expensive classical asymmetric cryptography, MPDC-I utilizes a hybrid asymmetric/symmetric post‐quantum secure design. This provides not only robust security but also scalability and computational efficiency, making it suitable for wide-scale adoption.

[MPDC Help Documentation](https://qrcs-corp.github.io/MPDC/)  
[MPDC Summary Document](https://qrcs-corp.github.io/MPDC/pdf/mpdc_summary.pdf)  
[MPDC Protocol Specification](https://qrcs-corp.github.io/MPDC/pdf/mpdc_specification.pdf)  
[MPDC Formal Analysis](https://qrcs-corp.github.io/MPDC/pdf/mpdc_formal.pdf)  
[MPDC Implementation Analysis](https://qrcs-corp.github.io/MPDC/pdf/mpdc_analysis.pdf)  
[MPDC Integration Guide](https://qrcs-corp.github.io/MPDC/pdf/mpdc_integration.pdf)  

## Architecture

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

## Compilation

MPDC uses the QSC cryptographic library. QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AES-NI, AVX2/AVX-512, and RDRAND.

### Prerequisites

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang  

### Building MPDC and the Client/Servers

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the server andc client projects: Agent, DLA, MAS, RDS, and Client.
Extract the files, and open the Server or Client project. The MPDC library has a default location in a folder parallel to the Server and Client project folders.  
The server and client projects additional files folder are set to: **$(SolutionDir)MPDC** and **$(SolutionDir)..\QSC\QSC**, if this is not the location of the library files, change it by going to server/client project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **[server/client]->References** property contains a reference to the MPDC library, and that the MPDC library contains a valid reference to the QSC library.  
QSC supports every AVX instruction family (AVX/AVX2/AVX-512).  
Set the QSC and MPDC libries and every server/client project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both QSC and MPDC to the same instruction set in Debug and Release Solution Configurations.  
Compile the QSC library (right-click and choose build), build the MPDC library, then build each individual server and client project.

#### MacOS / Ubuntu (Eclipse)

The QSC and the MPDC library projects, along with every server and client project have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse project files.  Copy those files directly into the folders containing the code files; move the files in the **Eclipse\Ubuntu\project-name** or **Eclipse\MacOS\project-name** folder to the folder containing the project's header and implementation files in MPDC and each server and client project.  
Create a new project for QSC, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, 'QSC'.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, and is set to No Enhanced Instructions by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


## License

INVESTMENT INQUIRIES:
QRCS is currently seeking a corporate investor for this technology.
Parties interested in licensing or investment should connect to us at: contact@qrcscorp.ca  
Visit https://www.qrcscorp.ca for a full inventory of our products and services.  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

License and Use Notice (2025-2026)  
This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation (QRCS) for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.  
All source code and materials in this repository are provided under the Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025-2026, unless explicitly stated otherwise.  
This license permits public access and non commercial research, evaluation, and testing use only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.  
The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.  
Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.  
For licensing inquiries, supported implementations, or commercial use, contact: licensing@qrcscorp.ca  
Quantum Resistant Cryptographic Solutions Corporation, 2026.  
_All rights reserved by QRCS Corp. 2026._