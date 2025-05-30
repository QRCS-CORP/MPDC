/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef MPDC_AGENT_H
#define MPDC_AGENT_H

#include "mpdccommon.h"

/**
 * \file agent.h
 * \brief MPDC Agent Server Interface.
 *
 * \details
 * This header defines the public functions for the MPDC Agent server, a key component of the MPDC network.
 * The Agent server is responsible for managing incoming network connections and processing protocol messages
 * specific to an agent device. Its duties include handling certificate generation and verification, responding
 * to topology convergence requests from the DLA, processing fragment query and master fragment key exchange
 * requests, and managing registration/resign operations.
 *
 * The Agent server implementation supports a wide range of protocol operations and user commands including:
 *
 * - **Certificate Management:** The Agent generates, imports, exports, and validates its own child certificate.
 *   It ensures that the certificate is correctly signed by the network's root and conforms to the MPDC certificate
 *   structure.
 *
 * - **Topology and Key Exchange:** The server handles convergence responses, fragment query responses, incremental
 *   updates, and master fragment key (mfk) exchange responses. These operations guarantee that the agent remains
 *   synchronized with the network topology and can securely participate in key exchange operations.
 *
 * - **Registration and Resignation:** The Agent server can register with the DLA (Domain List Agent) to join the
 *   MPDC network and send resign requests to remove itself from the network. Upon registration, the agent's certificate
 *   is propagated to the topology; on resignation, topology and key collections are reset.
 *
 * - **Command Loop and User Interaction:** A console-based command loop supports operations such as configuration,
 *   logging, service control (start/stop/pause/resume), and backup/restore of the agent's state. An idle timeout
 *   mechanism automatically logs out inactive sessions.
 *
 * - **Network Reception and Error Handling:** The Agent's receive loop processes various network packet flags (e.g.,
 *   converge request, fragment query, mfk request, revocation broadcast) and dispatches them to the appropriate
 *   internal functions. Detailed logging and error reporting ensure that issues such as socket failures,
 *   authentication errors, and protocol mismatches are detected and handled.
 *
 * \test
 * The Agent server implementation has been tested to verify that:
 *
 * - The server starts successfully (using both IPv4 and IPv6 configurations) and accepts incoming connections.
 * - Each network packet is correctly deserialized and dispatched based on its protocol flag.
 * - Certificate operations (generation, import, export, and validation) work as expected and adhere to the MPDC
 *   certificate format.
 * - Topology convergence, incremental update, and mfk exchange operations perform correctly under simulated network
 *   conditions.
 * - The command loop properly interprets and executes user commands and that the idle timeout mechanism logs out
 *   inactive sessions.
 *
 * These tests ensure both the correctness of the protocol operations and the robustness of the Agent server under
 * realistic network and user interaction scenarios.
 */

/**
 * \brief Pause the Agent server.
 *
 * This function pauses the MPDC Agent server, suspending the processing of network commands and user input.
 */
MPDC_EXPORT_API void mpdc_agent_pause_server();

/**
 * \brief Start the Agent server.
 *
 * This function initializes the MPDC Agent server by setting up the network socket for accepting
 * connections, initializing local state (including certificate and topology information), and starting
 * the main command and receive loops. It also spawns an idle timer thread to monitor user inactivity.
 *
 * \return Returns zero on success; a non-zero value indicates an initialization error.
 */
MPDC_EXPORT_API int32_t mpdc_agent_start_server();

/**
 * \brief Stop the Agent server.
 *
 * This function stops the MPDC Agent server, terminates the command loop and network receive loop,
 * and cleans up all allocated resources.
 */
MPDC_EXPORT_API void mpdc_agent_stop_server();


#endif
