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

#ifndef MPDC_CLIENT_H
#define MPDC_CLIENT_H

#include "mpdccommon.h"
#include "topology.h"

/**
 * \file client.h
 * \brief MPDC Client Functions.
 *
 * \details
 * This header defines the public interface for the MPDC client, which is responsible for handling
 * secure communications, certificate registration, topology queries, and tunnel establishment on the
 * client side of the Multi-Party Domain Cryptosystem (MPDC). The client module works in coordination
 * with other network components (e.g., MAS, DLA, and Agent) to provide a secure communication channel.
 *
 * Key functionalities include:
 *
 * - **Connection Evaluation:**  
 *   The client provides a callback function to evaluate incoming connection requests. This function
 *   examines the remote topology node requesting the connection and determines whether the connection
 *   should be accepted.
 *
 * - **Server Control Operations:**  
 *   Functions are provided to start, pause, and stop the client server. Starting the client server
 *   initializes network resources, loads certificates, sets up the user command loop, and begins listening
 *   for incoming connections. Pausing the server temporarily halts processing, while stopping the server
 *   gracefully terminates the client operation.
 *
 * - **Secure Tunnel and Topology Management:**  
 *   The client module handles master fragment key (mfk) exchanges, incremental updates to the network
 *   topology, and secure tunnel establishment. These functions ensure that the client maintains an up-to-date
 *   view of the network and can securely communicate with remote nodes.
 *
 * - **User Command Processing:**  
 *   A console-based command loop allows interactive configuration and operation of the client. Commands
 *   include certificate generation/import/export, connection requests, registration updates, and more.
 *
 * Testing:
 * The client module is validated through a series of network simulation tests which exercise:
 *
 * - The evaluation of incoming connection requests via the \ref mpdc_client_connect_callback().
 * - Registration with remote nodes, mfk key exchange, and topology synchronization.
 * - Secure tunnel establishment including both the transmit and receive paths.
 * - Proper handling of certificate expiration, error conditions, and user command processing.
 *
 * These tests collectively ensure that the client correctly implements the MPDC protocol and can maintain
 * secure and reliable communication within the network.
 */

/**
 * \brief Callback function to evaluate an incoming connection request.
 *
 * Use this callback to determine whether a remote node requesting connection should be accepted.
 *
 * \param rnode [in, const] The remote topology node requesting the connection.
 *
 * \return Returns true if the connection is accepted; otherwise, false.
 */
bool mpdc_client_connect_callback(const mpdc_topology_node_state* rnode);

/**
 * \brief Pause the Client server.
 *
 * Temporarily pause the MPDC client server, suspending network operations and the user command loop.
 */
MPDC_EXPORT_API void mpdc_client_pause_server();

/**
 * \brief Start the Client server.
 *
 * Initializes and starts the MPDC client server. This function sets up the network socket, loads the
 * local certificate, registers with the network topology, and begins the user command loop along with
 * the secure tunnel interface.
 *
 * \return Returns zero on success; a non-zero value indicates an initialization error.
 */
MPDC_EXPORT_API int32_t mpdc_client_start_server();

/**
 * \brief Stop the Client server.
 *
 * Terminates the MPDC client server, closing all active network connections and stopping the command loop.
 */
MPDC_EXPORT_API void mpdc_client_stop_server();


#endif