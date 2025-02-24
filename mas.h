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

#ifndef MPDC_MAS_H
#define MPDC_MAS_H

#include "common.h"
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
MPDC_EXPORT_API void mpdc_mas_pause_server();

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
MPDC_EXPORT_API int32_t mpdc_mas_start_server();

/**
 * \brief Stop the Application server.
 *
 * This function terminates all active server operations and releases resources.
 * It stops the command loop, closes all open network connections, and writes any
 * final log entries before shutting down.
 *
 * \note After stopping, the MAS can be restarted by calling mpdc_mas_start_server().
 */
MPDC_EXPORT_API void mpdc_mas_stop_server();

#endif