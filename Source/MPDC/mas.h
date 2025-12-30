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

#ifndef MPDC_MAS_H
#define MPDC_MAS_H

#include "mpdccommon.h"
#include "mpdc.h"

/**
 * \file mas.h
 * \brief The MPDC Application Server.
 *
 * The MPDC Application Server (MAS) is the primary server module in the MPDC system.
 * It is responsible for handling secure communication, processing application-level commands,
 * managing certificate operations, and maintaining the topology of connected nodes.
 *
 * The MAS operates as part of the overall MPDC network architecture. It supports key exchange,
 * secure message transport, and logs events to assist with debugging and diagnostics.
 *
 * The functions declared herein allow an application to start, pause, and stop the MAS. These
 * control functions are typically called by the main application to manage the server's lifecycle.
 *
 * \note It is essential that the MAS be properly configured before starting. Certificate files,
 * network settings, and key materials must be available and correct.
 *
 * Example usage:
 * \code
 *     // Start the MAS and check for success.
 *     if (mpdc_mas_start_server() == 0)
 *     {
 *         // Server is running; enter command loop or perform other tasks.
 *     }
 *     else
 *     {
 *         // Handle startup error.
 *     }
 *
 *     // To pause the server:
 *     mpdc_mas_pause_server();
 *
 *     // To fully stop the server:
 *     mpdc_mas_stop_server();
 * \endcode
 */

/**
 * \brief Pause the Application server.
 *
 * This function suspends the MAS command loop and stops processing new connections.
 * It is useful when temporary suspension of server activity is required without
 * fully shutting down the service.
 *
 * \note While paused, the MAS will not accept new connections until resumed or restarted.
 */
MPDC_EXPORT_API void mpdc_mas_pause_server(void);

/**
 * \brief Start the Application server.
 *
 * This function initializes the MAS environment, including:
 * - Setting up the console (virtual terminal, window size, title).
 * - Loading configuration data and certificates.
 * - Initializing secure sockets and key exchange mechanisms.
 * - Starting the main command loop for server operations.
 *
 * \return Returns 0 on successful startup; a negative error code otherwise.
 *
 * \note A return value of zero indicates that the MAS is ready to accept client connections.
 * Any non-zero return value signifies a failure, possibly due to configuration issues,
 * missing certificates, or insufficient system resources.
 */
MPDC_EXPORT_API int32_t mpdc_mas_start_server(void);

/**
 * \brief Stop the Application server.
 *
 * This function terminates all active server operations and releases resources.
 * It stops the command loop, closes all open network connections, and writes any
 * final log entries before shutting down.
 *
 * \note After stopping, the MAS can be restarted by calling mpdc_mas_start_server().
 */
MPDC_EXPORT_API void mpdc_mas_stop_server(void);

#endif
