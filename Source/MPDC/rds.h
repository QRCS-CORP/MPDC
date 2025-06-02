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
 * Contact: contact@qrcscorp.ca
 */

#ifndef MPDC_RDS_H
#define MPDC_RDS_H

#include "mpdccommon.h"

/**
 * \file rds.h
 * \brief The MPDC Root Domain Security server.
 *
 * Detailed File Description:
 * This header file defines the public interface for the MPDC Root Domain Security (RDS)
 * server. The RDS server is responsible for managing the root domain security functions within
 * the MPDC system. This includes handling operations related to the creation, storage, signing,
 * and verification of the root certificate as well as coordinating secure communications with
 * other nodes in the network. The public functions declared here allow the RDS server to be started,
 * paused, and stopped. In addition, when the macro MPDC_DEBUG_TESTS_RUN is defined, a test function
 * is provided to run self-diagnostic tests on the RDS server functionality.
 *
 * Every function declared in this header file is documented with its purpose, parameters, and return
 * value (if any).
 */

/**
 * \brief Pause the RDS server.
 *
 * This function pauses the operation of the RDS server. When called, the server will temporarily
 * suspend processing of incoming network messages and connections until it is resumed.
 */
MPDC_EXPORT_API void mpdc_rds_pause_server();

/**
 * \brief Start the RDS server.
 *
 * This function initializes and starts the RDS server. It sets up all necessary resources,
 * initializes the application state, and begins accepting network connections.
 */
MPDC_EXPORT_API void mpdc_rds_start_server();

/**
 * \brief Stop the RDS server.
 *
 * This function stops the RDS server by terminating its main command loop and releasing all allocated
 * resources. After calling this function, the server will no longer process incoming network messages.
 */
MPDC_EXPORT_API void mpdc_rds_stop_server();

#if defined(MPDC_DEBUG_TESTS_RUN)
/**
 * \brief Test the RDS server's functions.
 *
 * This function runs a suite of tests on the RDS server functions to verify proper operation of the
 * server's core features, such as certificate management and network communication.
 *
 * \return Returns true if all tests pass successfully, otherwise returns false.
 */
MPDC_EXPORT_API bool mpdc_rds_appserv_test();
#endif

#endif
