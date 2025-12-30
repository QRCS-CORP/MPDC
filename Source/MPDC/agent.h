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
MPDC_EXPORT_API void mpdc_agent_pause_server(void);

/**
 * \brief Start the Agent server.
 *
 * This function initializes the MPDC Agent server by setting up the network socket for accepting
 * connections, initializing local state (including certificate and topology information), and starting
 * the main command and receive loops. It also spawns an idle timer thread to monitor user inactivity.
 *
 * \return Returns zero on success; a non-zero value indicates an initialization error.
 */
MPDC_EXPORT_API int32_t mpdc_agent_start_server(void);

/**
 * \brief Stop the Agent server.
 *
 * This function stops the MPDC Agent server, terminates the command loop and network receive loop,
 * and cleans up all allocated resources.
 */
MPDC_EXPORT_API void mpdc_agent_stop_server(void);

#endif
