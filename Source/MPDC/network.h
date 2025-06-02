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

#ifndef MPDC_NETWORK_H
#define MPDC_NETWORK_H

#include "mpdccommon.h"
#include "topology.h"
#include "collection.h"
#include "sha3.h"
#include "socket.h"

/**
 * \file network.h
 * \brief The MPDC network functions.
 *
 * This header defines the public network functions and data types used by MPDC to
 * perform secure network operations. These operations include certificate announcement,
 * network convergence, registration and update of network nodes, key exchange, remote
 * signing, revocation, and topological queries.
 *
 * Each network message is encapsulated in a packet that includes a header (with a
 * time-stamp, sequence number, and flag), a payload, and a digital signature that
 * covers the payload and header. This ensures integrity, authenticity, and protection
 * against replay attacks.
 *
 * \note This header declares only the public API. Many internal functions (such as
 *       those for constructing and validating packet headers, hashing, signing, etc.)
 *       are defined as static in the implementation file.
 *
 * Example:
 * \code
 *   mpdc_network_announce_request_state req_state;
 *   req_state.list   = &global_topology_list;
 *   req_state.rnode  = &remote_node;
 *   req_state.sigkey = local_signing_key;
 *
 *   mpdc_protocol_errors err = mpdc_network_announce_broadcast(&req_state);
 *   if (err != mpdc_protocol_error_none)
 *   {
 *       // Handle error.
 *   }
 * \endcode
 */

/**
* \struct mpdc_network_announce_request_state
* \brief The certificate announce request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_announce_request_state
{
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_announce_request_state;

/**
* \struct mpdc_network_announce_response_state
* \brief The certificate announce response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_announce_response_state
{
	const mpdc_child_certificate* dcert;				/*!< A pointer to the dla certificate */
	mpdc_topology_node_state* rnode;					/*!< A pointer to the remote node */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
} mpdc_network_announce_response_state;

/**
* \struct mpdc_network_converge_request_state
* \brief The certificate converge request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_converge_request_state
{
	const mpdc_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	mpdc_topology_node_state* rnode;					/*!< A pointer to the remote node */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_converge_request_state;

/**
* \struct mpdc_network_converge_response_state
* \brief The certificate converge response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_converge_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const mpdc_child_certificate* lcert;				/*!< A pointer to the local certificate */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_converge_response_state;

/**
* \struct mpdc_network_converge_response_verify_state
* \brief The certificate converge verify function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_converge_response_verify_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the remote certificate */
} mpdc_network_converge_response_verify_state;

/**
* \struct mpdc_network_converge_update_verify_state
* \brief The certificate converge update verify function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_converge_update_verify_state
{
	const qsc_socket* csock;									/*!< A pointer to the connected socket */
	mpdc_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_converge_update_verify_state;

/**
* \struct mpdc_network_fkey_request_state
* \brief The fkey request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_fkey_request_state
{
	uint8_t* frag;										/*!< A pointer to the key fragment */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node */
	const uint8_t* mfk;									/*!< A pointer to the master fragment key */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node */
	uint8_t* token;										/*!< A pointer to the exchange token */
} mpdc_network_fkey_request_state;

/**
* \struct mpdc_network_fkey_response_state
* \brief The fkey response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_fkey_response_state
{
	qsc_socket* csock;									/*!< A pointer to the connected socket */
	uint8_t* frag;										/*!< A pointer to the key fragment */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node */
	const uint8_t* mfk;									/*!< A pointer to the master fragment key */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node */
} mpdc_network_fkey_response_state;

/**
* \struct mpdc_network_incremental_update_request_state
* \brief The incremental update request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_incremental_update_request_state
{
	mpdc_child_certificate* rcert;						/*!< A pointer to the output remote certificate */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
} mpdc_network_incremental_update_request_state;

/**
* \struct mpdc_network_incremental_update_response_state
* \brief The incremental update response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_incremental_update_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the output remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_incremental_update_response_state;

/**
* \struct mpdc_network_register_request_state
* \brief The network join request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_register_request_state
{
	const char* address;								/*!< The dla server address */
	const mpdc_child_certificate* lcert;				/*!< A pointer to the local certificate */
	mpdc_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_register_request_state;

/**
* \struct mpdc_network_register_response_state
* \brief The network join response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_register_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const mpdc_child_certificate* lcert;				/*!< A pointer to the local certificate */
	mpdc_child_certificate* rcert;						/*!< A pointer to the output remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_register_response_state;

/**
* \struct mpdc_network_register_update_request_state
* \brief The network join request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_register_update_request_state
{
	const char* address;								/*!< The server address */
	const mpdc_child_certificate* lcert;				/*!< A pointer to the local certificate */
	mpdc_topology_list_state* list;						/*!< A pointer to the topology list */
	mpdc_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_register_update_request_state;

/**
* \struct mpdc_network_register_update_response_state
* \brief The network join update response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_register_update_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const mpdc_child_certificate* lcert;				/*!< A pointer to the local certificate */
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	mpdc_child_certificate* rcert;						/*!< A pointer to the output remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_register_update_response_state;

/**
* \struct mpdc_network_mfk_request_state
* \brief The mfk request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_mfk_request_state
{
	const mpdc_child_certificate* lcert;				/*!< A pointer to the local certificate */
	uint8_t* mfk;										/*!< A pointer to the master fragment key */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_mfk_request_state;

/**
* \struct mpdc_network_mfk_response_state
* \brief The mfk response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_mfk_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	mpdc_cipher_keypair ckp;							/*!< The asymmetric encryption keypair */
	const mpdc_child_certificate* lcert;				/*!< A pointer to the local certificate */
	uint8_t* mfk;										/*!< A pointer to the master fragment key */
	mpdc_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_mfk_response_state;

/**
* \struct mpdc_network_remote_signing_request_state
* \brief The certificate remote signing request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_remote_signing_request_state
{
	const char* address;								/*!< The rds server address */
	mpdc_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_remote_signing_request_state;

/**
* \struct mpdc_network_remote_signing_response_state
* \brief The certificate remote signing response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_remote_signing_response_state
{
	qsc_socket* csock;									/*!< A pointer to the connected socket */
	mpdc_child_certificate* dcert;						/*!< A pointer to the dla certificate */
	mpdc_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const mpdc_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_remote_signing_response_state;

/**
* \struct mpdc_network_resign_request_state
* \brief The certificate resign request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_resign_request_state
{
	const char* address;								/*!< The server address */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_resign_request_state;

/**
* \struct mpdc_network_resign_response_state
* \brief The certificate resign request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_resign_response_state
{
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	mpdc_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	mpdc_topology_node_state* rnode;					/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_resign_response_state;

/**
* \struct mpdc_network_revoke_request_state
* \brief The certificate revoke request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_revoke_request_state
{
	mpdc_network_designations designation;				/*!< The node type designation */
	const mpdc_topology_list_state* list;				/*!< A pointer to the node database */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_revoke_request_state;

/**
* \struct mpdc_network_revoke_response_state
* \brief The certificate revoke response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_revoke_response_state
{
	const mpdc_topology_list_state* list;				/*!< A pointer to the node database */
	mpdc_topology_node_state* rnode;					/*!< A pointer to the remote node structure */
	const mpdc_child_certificate* dcert;				/*!< A pointer to the dla certificate */
} mpdc_network_revoke_response_state;

/**
* \struct mpdc_network_topological_query_request_state
* \brief The topological query request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_topological_query_request_state
{
	const mpdc_child_certificate* dcert;				/*!< A pointer to the dla certificate */
	mpdc_topology_node_state* dnode;					/*!< A pointer to the dla node node structure */
	const char* issuer;									/*!< A pointer to the query issuer string */
	mpdc_topology_node_state* rnode;					/*!< A pointer to the return remote node structure */
	const uint8_t* serial;								/*!< A pointer to the local serial number */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_topological_query_request_state;

/**
* \struct mpdc_network_incremental_update_response_state
* \brief The topological query response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_topological_query_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const mpdc_child_certificate* ccert;				/*!< A pointer to the remote clients certificate */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_topological_query_response_state;

/**
* \struct mpdc_network_topological_status_request_state
* \brief The topological status request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_topological_status_request_state
{
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the client responder certificate */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_topological_status_request_state;

/**
* \struct mpdc_network_topological_status_response_state
* \brief The topological status response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_topological_status_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_topological_status_response_state;

/**
* \struct mpdc_network_fragment_collection_request_state
* \brief The fkey collection request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_fragment_collection_request_state
{
	qsc_socket* csock;									/*!< The connected socket */
	uint8_t* hfkey;										/*!< A pointer to the fkeys hash */
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the remote node structure */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	uint8_t* token;										/*!< A pointer to the client token */
} mpdc_network_fragment_collection_request_state;

/**
* \struct mpdc_network_fragment_collection_response_state
* \brief The fkey collection response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_fragment_collection_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	uint8_t* frag;										/*!< A pointer to the key fragment */
	uint8_t* hfkey;										/*!< A pointer to the fkeys hash */
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	uint8_t* ctok;										/*!< A pointer to the client token */
	uint8_t* mtok;										/*!< A pointer to the server token */
} mpdc_network_fragment_collection_response_state;

/**
* \struct mpdc_network_fragment_query_request_state
* \brief The fkey query request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_fragment_query_request_state
{
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the client node structure */
	const uint8_t* token;								/*!< A pointer to the local token */
} mpdc_network_fragment_query_request_state;

/**
* \struct mpdc_network_fragment_query_response_state
* \brief The fkey query response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_fragment_query_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const mpdc_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const mpdc_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
} mpdc_network_fragment_query_response_state;

/**
* \struct mpdc_network_key_exchange_request_state
* \brief The key exchange request function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_key_exchange_request_state
{
	const char* address;								/*!< The server address */
	mpdc_connection_state* cns;							/*!< The connection state */
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the output remote certificate */
	const uint8_t* token;								/*!< A pointer to a token */
} mpdc_network_key_exchange_request_state;

/**
* \struct mpdc_network_key_exchange_response_state
* \brief The key exchange response function state
*/
MPDC_EXPORT_API typedef struct mpdc_network_key_exchange_response_state
{
	mpdc_connection_state* cns;							/*!< The connection state */
	const qsc_socket* csock;							/*!< The connected socket */
	const mpdc_topology_list_state* list;				/*!< A pointer to the topology list */
	const mpdc_child_certificate* rcert;				/*!< A pointer to the output remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} mpdc_network_key_exchange_response_state;

/*---------------------------------------------------------------------------
  Public Function Prototypes
---------------------------------------------------------------------------*/

/**
* \brief Announce a certificate using the dla, and broadcast it to the network
*
* \param state: The announce state structure
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_announce_broadcast(mpdc_network_announce_request_state* state);

/**
* \brief Process a announce response message
*
* \param state: The announce response state structure
* \param packetin: [const] The input packet containing the announce request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_announce_response(mpdc_network_announce_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Gets the network designation from a port number
*
* \param tnode: The target network designation type
* \return Returns the port number, or zero if the node type is invalid
*/
MPDC_EXPORT_API uint16_t mpdc_network_application_to_port(mpdc_network_designations tnode);

/**
* \brief Broadcast a message to a node type on the network
*
* \param list: [const] A pointer to the topology list
* \param message: The message to send
* \param msglen: The length of the message
* \param tnode: The target node-type designation
*/
MPDC_EXPORT_API void mpdc_network_broadcast_message(const mpdc_topology_list_state* list, const uint8_t* message, size_t msglen, mpdc_network_designations tnode);

/**
* \brief Connect a socket to a remote address
*
* \param csock: A pointer to the socket
* \param address: [const] The remote hosts address
* \param designation: The remote hosts designation
* \return Returns the socket error
*/
MPDC_EXPORT_API qsc_socket_exceptions mpdc_network_connect_to_device(qsc_socket* csock, const char* address, mpdc_network_designations designation);

/**
* \brief The DLA sends out a convergence request, and broadcast it to the network
*
* \param state: The converge request state structure
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_converge_request(const mpdc_network_converge_request_state* state);

/**
* \brief Respond to a dla network converge request
*
* \param state: The converge response state structure
* \param packetin: [const] The input packet containing the verify response
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_converge_response(const mpdc_network_converge_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Process a converge response update message
*
* \param state: The converge update verify state structure
* \param packetin: [const] The input packet containing the verify response
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_converge_update_verify(mpdc_network_converge_update_verify_state* state, const mpdc_network_packet* packetin);

/**
* \brief Connect a socket to a remote address and port
*
* \param csock: A pointer to the socket
* \param address: [const] The remote hosts address
* \param port: The application port number
* \return Returns the socket error
*/
MPDC_EXPORT_API qsc_socket_exceptions mpdc_network_connect_to_address(qsc_socket* csock, const char* address, uint16_t port);

/**
* \brief Request and execute a key exchange for a fragmentation key
*
* \param state: The fkey request state structure
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_fkey_request(mpdc_network_fkey_request_state* state);

/**
* \brief Respond and execute a key exchange for a fragmentation key
*
* \param state: The fkey response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_fkey_response(mpdc_network_fkey_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief A Client requests a fragment collection from a MAS
*
* \param state: The fragment collection request state
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_fragment_collection_request(mpdc_network_fragment_collection_request_state* state);

/**
* \brief A MAS sends a collection response to a Client
*
* \param state: The fkey response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_fragment_collection_response(mpdc_network_fragment_collection_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief An Agent sends a fragment query response to a MAS
*
* \param state: The fragment query response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_fragment_query_response(const mpdc_network_fragment_query_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Get the local IP address
*
* \param address: The output address byte array
* \return Returns true if the address is retrieved
*/
MPDC_EXPORT_API bool mpdc_network_get_local_address(char address[MPDC_CERTIFICATE_ADDRESS_SIZE]);

/**
* \brief Send an error message
*
* \param csock: A pointer to the socket
* \param error: The error code
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_send_error(const qsc_socket* csock, mpdc_protocol_errors error);

/**
* \brief Shut down and dispose of a socket instance
*
* \param csock: A pointer to the socket
*/
MPDC_EXPORT_API void mpdc_network_socket_dispose(qsc_socket* csock);

/**
* \brief Send an incremental update request
*
* \param state: The incremental update request function state
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_incremental_update_request(const mpdc_network_incremental_update_request_state* state);

/**
* \brief Send a copy of a certificate to a remote host
*
* \param state: The update response function state
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_incremental_update_response(const mpdc_network_incremental_update_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Send an Agent join request to the DLA
*
* \param state: The join request function state
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_register_request(mpdc_network_register_request_state* state);

/**
* \brief Send a MAS or Client join update request to the DLA
*
* \param state: The join update request function state
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_register_update_request(mpdc_network_register_update_request_state* state);

/**
* \brief Send a join response to the agent
*
* \param state: The join response function state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_register_response(mpdc_network_register_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Send a join update response to the server or client
*
* \param state: The join response function state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_register_update_response(mpdc_network_register_update_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Send a certificate signing request from the DLA to the RDS
*
* \param state: The remote signing request state
* \return Returns a protocol error flag
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_remote_signing_request(mpdc_network_remote_signing_request_state* state);

/**
* \brief Send a signed certificate response from the RDS to the DLA
*
* \param state: The remote signing response state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_remote_signing_response(mpdc_network_remote_signing_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Request and execute a key exchange request for a master fragmentation key
*
* \param state: The mfk request state structure
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_mfk_exchange_request(mpdc_network_mfk_request_state* state);

/**
* \brief Request and execute a key exchange response for a master fragmentation key
*
* \param state: The mfk response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_mfk_exchange_response(mpdc_network_mfk_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Gets the network designation from a port number
*
* \param port: The network application port
* \return Returns the network designation type
*/
MPDC_EXPORT_API mpdc_network_designations mpdc_network_port_to_application(uint16_t port);

/**
* \brief Verify a certificates format and root signature
*
* \param ccert: [const] The child certificate
* \param root: [const] The root certificate
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_certificate_verify(const mpdc_child_certificate* ccert, const mpdc_root_certificate* root);

/**
* \brief Send a resign request to the dla
*
* \param state: The resign request state structure
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_resign_request(const mpdc_network_resign_request_state* state);

/**
* \brief Send a resign response to the agent or server
*
* \param state: The resign response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_resign_response(mpdc_network_resign_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Send a revocation request from the DLA
*
* \param state: The revocation broadcast function state
* \return Returns a protocol error flag
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_revoke_broadcast(mpdc_network_revoke_request_state* state);

/**
* \brief Verify a revocation request sent from the DLA
*
* \param state: The revocation verify function state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_revoke_response(mpdc_network_revoke_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Query a device for its topological information
*
* \param state: The topological query request state
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_topological_query_request(const mpdc_network_topological_query_request_state* state);

/**
* \brief Respond to a topological query request
*
* \param state: topological query response state
* \param packetin: The packet containing the topological query request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_topological_query_response(const mpdc_network_topological_query_response_state* state, const mpdc_network_packet* packetin);

/**
* \brief Send a status request from the DLA to a client device
*
* \param state: The topological status request state
* \param query: The device query string
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_topological_status_request(const mpdc_network_topological_status_request_state* state);

/**
* \brief Verify the status response from the DLA
*
* \param state: The topological status verify state
* \param packetin: The packet containing the topological status response
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_topological_status_verify(const mpdc_network_topological_status_request_state* state, const mpdc_network_packet* packetin);

/**
* \brief Process the status response from the client device and send a response
*
* \param state: The topological status response state
* \param packetin: The packet containing the topological status request
* \return Returns the error code
*/
MPDC_EXPORT_API mpdc_protocol_errors mpdc_network_topological_status_response(const mpdc_network_topological_status_response_state* state, const mpdc_network_packet* packetin);

#if defined(MPDC_DEBUG_MODE)
MPDC_EXPORT_API bool mpdc_network_protocols_test(void);
#endif

#endif
