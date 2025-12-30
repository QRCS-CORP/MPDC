/* 2024-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef MPDC_DOXYMAIN_H
#define MPDC_DOXYMAIN_H

/**
 * \mainpage Multi Party Domain Cryptosystem (MPDC-I)
 *
 * \section intro_sec Introduction
 *
 * MPDC-I (Multi Party Domain Cryptosystem - Interior Protocol) is a multi‐party key exchange and network security system.
 * It distributes the security of a key exchange between a server and a client across multiple devices.
 * This design leverages the contribution of network agents -trusted devices that each inject a portion
 * of pseudo‐random material into the key exchange process, ensuring that no single entity controls the
 * entire shared-secret derivation.
 *
 * On an interior network, the server and client establish a shared secret with each authenticated agent
 * using an asymmetric key exchange. The resulting shared-secret, retained for the lifetime of the device's certificate,
 * is used to generate a unique key-stream to encrypt small chunks of pseudo‐random data called "key fragments".
 * These fragments are subsequently combined and hashed to derive the primary session keys that secure the
 * encrypted tunnel between the server and client.
 *
 * This approach means that any attack involving impersonation or man‐in‐the‐middle tactics would have to
 * simultaneously compromise multiple, independently authenticated network devices. Unlike other schemes that
 * rely solely on expensive classical asymmetric cryptography, MPDC-I utilizes a hybrid asymmetric/symmetric
 * post‐quantum secure design. This provides not only robust security but also scalability and computational
 * efficiency, making it suitable for wide-scale adoption.
 *
 * \section arch_sec Architecture Overview
 *
 * MPDC-I operates with five key device types, each fulfilling a distinct role within the security ecosystem:
 *
 * \subsection client_sec Client
 * **Role:** An end-user network device that initiates secure communication with the MPDC-enabled
 * Application Server.
 *
 * **Functions:**
 * - Generates its own certificate and stores the secret signing key.
 * - Has its certificate signed by the RDS (Root Domain Security), either directly or by proxy through the DLA.
 * - Exchanges master fragment keys (mfk) with Agents and MAS servers, which are used to encrypt key fragments.
 * - Combines key fragments received from Agents with the MAS fragment key to derive secure session keys.
 * - Encrypts and decrypts messages using the session keys through a duplexed, encrypted, and authenticated tunnel.
 *
 * \subsection mas_sec MAS (MPDC Application Server)
 * **Role:** Acts as the central application server managing secure communications with Clients.
 *
 * **Functions:**
 * - Generates its own certificate and stores the secret signing key.
 * - Has its certificate signed by the RDS, directly or via the DLA.
 * - Validates Client certificates against the RDS root certificate.
 * - Communicates with Agents to obtain key fragments.
 * - Derives session keys used to securely interact with Clients.
 * - Encrypts and decrypts messages over a duplexed, secure tunnel.
 *
 * \subsection agent_sec Agent
 * **Role:** A trusted network device that injects additional entropy into the key exchange process.
 *
 * **Functions:**
 * - Generates its own certificate and stores its secret signing key.
 * - Has its certificate signed by the RDS, either directly or via the DLA.
 * - Generates key fragments (providing pseudo‐random entropy) for session key derivation.
 * - Securely transmits key fragments to both the MAS and Clients.
 * - Enhances the overall security of session keys through independent cryptographic processes.
 *
 * \subsection dla_sec DLA (Domain List Agent)
 * **Role:** Manages device registration and certificate validation within the network.
 *
 * **Functions:**
 * - Generates its own certificate and stores the secret signing key.
 * - Has its certificate signed by the RDS.
 * - Validates device certificates using the RDS certificate.
 * - Maintains a master list of trusted devices (network topology).
 * - Distributes certificates and topology updates.
 * - Manages certificate revocation and device resignation.
 * - Handles topological queries from network devices.
 *
 * \subsection rds_sec RDS (Root Domain Security Server)
 * **Role:** Serves as the root certificate authority (trust anchor) for the network.
 *
 * **Functions:**
 * - Generates and manages the root certificate.
 * - Signs device certificates to authenticate identity and trust.
 * - May operate as a certificate signing proxy in conjunction with the DLA.
 *
 * \section protocol_sec MPDC-I Protocol Overview
 *
 * MPDC-I distributes the key exchange security across multiple devices:
 * - **Key Fragment Exchange:** Each Agent on the network, authenticated by the RDS, contributes a
 *   unique key fragment. These fragments are generated using computationally inexpensive symmetric
 *   cryptography.
 * - **Session Key Derivation:** The MAS and Client combine key fragments from all participating Agents
 *   with a MAS-specific fragment key. This combination is hashed to derive the primary session keys used
 *   to encrypt the communication tunnel.
 * - **Security Benefits:** An adversary must impersonate multiple devices simultaneously to break the
 *   session keys, making man-in-the-middle attacks practically infeasible.
 * - **Hybrid Cryptography:** MPDC-I employs a post-quantum secure hybrid model combining asymmetric
 *   and symmetric cryptography, achieving both high security and efficient performance.
 *
 * \section config_sec MPDC Example Configuration
 *
 * The following steps outline a typical configuration and network initialization process:
 *
 * - **RDS Initialization:**
 *   - Log in to the RDS server and issue the 'enable' command.
 *   - Configure your user name, password, device name, IP address, and network name.
 *   - Switch to config mode, then certificate mode.
 *   - Generate a root certificate with the command:
 *     - 'generate(days-valid)' (specify the certificate validity period in days).
 *
 * - **DLA Initialization:**
 *   - Log in to the DLA server and issue the 'enable' command.
 *   - When prompted, supply the path to the root certificate generated by the RDS.
 *   - Switch to certificate mode and generate the DLA certificate.
 *
 * - **RDS Certificate Signing:**
 *   - On the RDS, switch to certificate mode and sign the DLA's certificate using:
 *     - 'sign(certificate-path)' (where *certificate-path* is the file path to the DLA certificate).
 *   - Transfer the signed certificate back to the DLA either manually (server restart may be required)
 *     or using the import command in certificate mode.
 *
 * - **Device Initialization (Agent, MAS, Client):**
 *   - For each device (Agent, MAS, and Client), generate a certificate and corresponding key-pair.
 *   - Get each certificate signed by the RDS directly or via the DLA.
 *   - Register each device with the DLA, which validates the certificate and updates the network topology.
 *
 * - **MAS and Agent Integration:**
 *   - On the MAS, join the network by contacting the DLA and obtaining a list of available Agents.
 *   - Enable the IP service on the MAS.
 *   - On each Agent, enable the IP service and register with the DLA using:
 *     - 'register(dla-ip-address)'.
 *
 * - **Client Integration:**
 *   - On each Client, enable the IP service and register with the DLA.
 *   - Exchange certificates and master fragment keys with Agents and the MAS.
 *   - In server mode, use the command 'connect(mas-ip-address)' to establish an encrypted tunnel with a MAS.
 *
 * \section file_sec File Description
 *
 * The MPDC library is modular and organized as follows:
 *
 * - **mpdc.h:** Contains the primary MPDC library api, including constants, structures, and functions used by all servers and clients.
 * - **server.h:** Contains common server functions for managing configuration, state, certificates, logging,
 *   and topology.
 * - **network.h:** Provides secure communication protocols, key exchanges, and certificate management routines.
 * - **topology.h:** Manages the network topology, including node registration, serialization, and updates.
 * - **trust.h:** Handles trust metrics for network devices including serialization and deserialization of trust
 *   structures.
 * - **agent.h:** Implements the Agent security server functionality.
 * - **client.h:** Implements the MPDC Client functionality.
 * - **dla.h:** Implements the Domain List Agent server functionality.
 * - **mas.h:** Implements the MPDC Application Server functionality.
 * - **rds.h:** Implements the Root Domain Security server functionality.
 *
 * \section usage_sec Getting Started
 *
 * To use the MPDC library:
 * - Include the necessary header files in your project (e.g., \c server.h, \c network.h, \c topology.h, \c trust.h, \c rds.h).
 * - Initialize the appropriate server type (Client, MAS, Agent, DLA, or RDS) via the provided API functions.
 * - Follow the configuration steps detailed above to properly set up your secure MPDC network.
 *
 * \subsection library_dependencies Cryptographic Dependencies
 * QSTP uses the QSC cryptographic library: <a href="https://github.com/QRCS-CORP/QSC">The QSC Library</a>
 * 
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 * 
 * \author John G. Underhill
 * \date 2025-02-10
 */

#endif
