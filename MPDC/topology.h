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

#ifndef MPDC_TOPOLOGY_H
#define MPDC_TOPOLOGY_H

#include "mpdc.h"
#include "certificate.h"
#include "../../QSC/QSC/ipinfo.h"
#include "../../QSC/QSC/list.h"
#include "../../QSC/QSC/timestamp.h"

/**
 * \file topology.h
 * \brief The MPDC topology functions.
 * 
 * Detailed File Description:
 * This header file defines the functions, macros, structures, and enumerations used by MPDC for managing the
 * network topology. The topology functions handle the serialization and deserialization of network node information,
 * conversion between canonical and issuer names, registration and removal of nodes from the topology list, and
 * various lookup and verification operations.
 * 
 * Notes:
 * The issuer parameter composition; network/host.ctype:alias
 * The first segment of an issuer string consists of the network path, which is the network name, appended with a
 * forward slash (network/host). A network name can contain subdomains, each ending in a forward slash, ex. domain/subdomain/host.
 * The network portion of the issuer string represents the network and host names as a path string.
 * The second segment is the host name, and an optional extension preceded by a period (host.type), ex. xyz/mas.ctype.
 * There are three types of devices; root, intra-domain, and inter-domain, which correspond to MPDC device types of [root server],
 * [dla, agent, mas, client], and [idg] inter-domain gateways.
 * The third segment of the issuer string is the alias (path:alias), a readable domain alias name, always preceded by a colon.
 * The network name and any subdomains are always preceded by a single forward slash (domain/subdomain). ex. network/sub-network/host.
 * The host name is the network device name, and it is terminated with a colon (path:alias).
 * The alias is a name that represents a compact path or string representation of the network\node path.
 * Example: xyz/mas-1:www.xyz.com
 * The entire issuer string cannot exceed 256 bytes.
 * Periods, dashes, and most other symbols are legal with the exception of the reserved symbols: period, forward slash, and colon (. / :),
 * as well as illegal symbols such as ! @ $ % ^ & * ( ) { } | ; " '.
 * Name to address lookups can be performed by the DLA that can translate a network\node path, or an alias name, to an IP address
 * (IPv4 or IPv6). Inverse lookups can also be performed, which return the issuer string from an IP address.
 * Issuer network paths are mirrored in the storage subsystem and used as storage path substrings (e.g., C:\MPDC\xyz\mas),
 * enabling file system certificate retrieval based on the issuer's topological path.
 */

/*---------------------------------------------------------------------------
  MACRO DEFINITIONS
---------------------------------------------------------------------------*/

/*!
 * \def MPDC_TOPOLOGY_NODE_ENCODED_SIZE
 * \brief The size of an encoded node string.
 *
 * This macro defines the size of a printable, encoded node string. Its value depends on whether the network is
 * IPv6 or IPv4.
 */
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
#	define MPDC_TOPOLOGY_NODE_ENCODED_SIZE (MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE + MPDC_CERTIFICATE_ISSUER_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE + QSC_IPINFO_IPV6_STRNLEN + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_ROOT_CERTIFICATE_HASH_PREFIX_SIZE + (MPDC_CERTIFICATE_HASH_SIZE * 2) + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE + (MPDC_CERTIFICATE_SERIAL_SIZE * 2) + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE + MPDC_NETWORK_DESIGNATION_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE + QSC_TIMESTAMP_STRING_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE + QSC_TIMESTAMP_STRING_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE)
#else
#	define MPDC_TOPOLOGY_NODE_ENCODED_SIZE (MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE + MPDC_CERTIFICATE_ISSUER_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE + QSC_IPINFO_IPV4_STRNLEN + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_ROOT_CERTIFICATE_HASH_PREFIX_SIZE + (MPDC_CERTIFICATE_HASH_SIZE * 2) + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE + (MPDC_CERTIFICATE_SERIAL_SIZE * 2) + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE + MPDC_NETWORK_DESIGNATION_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE + QSC_TIMESTAMP_STRING_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE + \
	MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE + QSC_TIMESTAMP_STRING_SIZE + MPDC_CERTIFICATE_SEPERATOR_SIZE)
#endif

/*!
 * \def MPDC_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE
 * \brief The minimum size of an issuer string.
 */
#define MPDC_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE 3

/*!
 * \def MPDC_TOPOLOGY_NODE_NOT_FOUND
 * \brief The value returned when a node is not found.
 */
#define MPDC_TOPOLOGY_NODE_NOT_FOUND -1

/*!
 * \def MPDC_NETWORK_TOPOLOGY_MAX_SIZE
 * \brief The maximum size of the topology.
 */
#define MPDC_NETWORK_TOPOLOGY_MAX_SIZE 1024

/*!
 * \def MPDC_NETWORK_TOPOLOGY_NODE_SIZE
 * \brief The size in bytes of a serialized topological node.
 */
#define MPDC_NETWORK_TOPOLOGY_NODE_SIZE (MPDC_CERTIFICATE_ADDRESS_SIZE + \
	MPDC_CERTIFICATE_HASH_SIZE + \
	MPDC_CERTIFICATE_SERIAL_SIZE + \
	MPDC_CERTIFICATE_ISSUER_SIZE + \
	MPDC_CERTIFICATE_EXPIRATION_SIZE + \
	MPDC_CERTIFICATE_DESIGNATION_SIZE)

/*---------------------------------------------------------------------------
  STATIC CONSTANTS
---------------------------------------------------------------------------*/

/*!
 * \brief The delimiter used in network topology for network path segments.
 */
static const char MPDC_TOPOLOGY_NETWORK_DELIMITER[] = "/";

/*!
 * \brief The delimiter used between the host name and certificate type.
 */
static const char MPDC_TOPOLOGY_CTYPE_DELIMITER[] = ".";

/*!
 * \brief The delimiter used for alias in the issuer string.
 */
static const char MPDC_TOPOLOGY_ALIAS_DELIMITER[] = ":";

/*---------------------------------------------------------------------------
  DATA STRUCTURES
---------------------------------------------------------------------------*/

/*!
 * \struct mpdc_topology_node_state
 * \brief The MPDC topology node structure.
 *
 * This structure represents a network node in the topology database.
 */
MPDC_EXPORT_API typedef struct mpdc_topology_node_state
{
	char address[MPDC_CERTIFICATE_ADDRESS_SIZE];		/*!< The device's network address. */
	uint8_t chash[MPDC_CERTIFICATE_HASH_SIZE];			/*!< A hash of the device's certificate. */
	uint8_t serial[MPDC_CERTIFICATE_SERIAL_SIZE];		/*!< The certificate serial number. */
	char issuer[MPDC_CERTIFICATE_ISSUER_SIZE];			/*!< The certificate issuer string. */
	mpdc_certificate_expiration expiration;				/*!< The certificate expiration times (valid from and to). */
	mpdc_network_designations designation;				/*!< The device's topological designation. */
} mpdc_topology_node_state;

/*!
 * \struct mpdc_topology_list_state
 * \brief The MPDC topology list structure.
 *
 * This structure represents the complete list of network nodes in the topology.
 */
MPDC_EXPORT_API typedef struct mpdc_topology_list_state
{
	uint8_t* topology;									/*!< Pointer to the serialized topology array. */
	uint32_t count;										/*!< The number of active nodes in the topology. */
} mpdc_topology_list_state;

/*---------------------------------------------------------------------------
  FUNCTION PROTOTYPES
---------------------------------------------------------------------------*/

/**
 * \brief Returns an IP address from an issuer string.
 *
 * This function extracts and returns the network address associated with a given issuer string,
 * using the topology list to resolve the address.
 *
 * \param address The output buffer to receive the node's network address (max MPDC_CERTIFICATE_ADDRESS_SIZE).
 * \param issuer [const] The issuer string.
 * \param list [const] A pointer to the topology list.
 */
MPDC_EXPORT_API void mpdc_topology_address_from_issuer(char* address, const char* issuer, const mpdc_topology_list_state* list);

/**
 * \brief Add an alias string to an issuer path.
 *
 * This function appends an alias to the issuer string of a node.
 *
 * \param node The network node to update.
 * \param alias [const] The host alias to add.
 */
MPDC_EXPORT_API void mpdc_topology_node_add_alias(mpdc_topology_node_state* node, const char* alias);

/**
 * \brief Compare two topological nodes for equality.
 *
 * This function compares two topology node structures and returns true if they are identical.
 *
 * \param a [const] The first node.
 * \param b [const] The second node.
 * \return Returns true if the nodes are identical; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_nodes_are_equal(const mpdc_topology_node_state* a, const mpdc_topology_node_state* b);

/**
 * \brief Get an empty node pointer from the topology list.
 *
 * This function returns a pointer to an empty node entry in the topology list.
 * \note This function is not thread safe.
 *
 * \param list A pointer to the topology list.
 * \return Returns a pointer to the empty node entry or NULL if none is available.
 */
MPDC_EXPORT_API uint8_t* mpdc_topology_child_add_empty_node(mpdc_topology_list_state* list);

/**
 * \brief Add a node to the topology list.
 *
 * This function adds a new node item to the topology list.
 *
 * \param list A pointer to the topology list.
 * \param node [const] The node to add.
 */
MPDC_EXPORT_API void mpdc_topology_child_add_item(mpdc_topology_list_state* list, const mpdc_topology_node_state* node);

/**
 * \brief Translate a canonical name to an issuer name.
 *
 * This function converts a device canonical name into its corresponding issuer name based on the domain.
 *
 * \param issuer The output issuer string.
 * \param isslen The length of the issuer buffer.
 * \param domain The domain name.
 * \param cname The input device canonical name.
 * \return Returns false if the conversion fails.
 */
MPDC_EXPORT_API bool mpdc_topology_canonical_to_issuer_name(char* issuer, size_t isslen, const char* domain, const char* cname);

/**
 * \brief Translate an issuer name to a canonical name.
 *
 * This function converts an issuer name back into its canonical form.
 *
 * \param cname The output canonical name.
 * \param namelen The length of the canonical name buffer.
 * \param issuer The input issuer name string.
 * \return Returns false if the conversion fails.
 */
MPDC_EXPORT_API bool mpdc_topology_issuer_to_canonical_name(char* cname, size_t namelen, const char* issuer);

/**
 * \brief Register a child to a topology list.
 *
 * This function registers a new child node in the topology list based on its certificate.
 *
 * \param list A pointer to the topology list.
 * \param ccert [const] The node's child certificate.
 * \param address [const] The node's network address (max MPDC_CERTIFICATE_ADDRESS_SIZE).
 */
MPDC_EXPORT_API void mpdc_topology_child_register(mpdc_topology_list_state* list, const mpdc_child_certificate* ccert, const char* address);

/**
 * \brief Clone a topology list.
 *
 * This function creates a clone of the given topology list.
 *
 * \param tlist [const] A pointer to the source topology list.
 * \param tcopy A pointer to the destination topology list.
 */
MPDC_EXPORT_API void mpdc_topology_list_clone(const mpdc_topology_list_state* tlist, mpdc_topology_list_state* tcopy);

/**
 * \brief Deserialize a topology list.
 *
 * This function deserializes a topology list from a given input array.
 *
 * \param list A pointer to the topology list state to populate.
 * \param input [const] The serialized topology array.
 * \param inplen The size of the input array.
 */
MPDC_EXPORT_API void mpdc_topology_list_deserialize(mpdc_topology_list_state* list, const uint8_t* input, size_t inplen);

/**
 * \brief Dispose of the topology list and release memory.
 *
 * This function releases all memory allocated for the topology list.
 *
 * \param list A pointer to the topology list state.
 */
MPDC_EXPORT_API void mpdc_topology_list_dispose(mpdc_topology_list_state* list);

/**
 * \brief Initialize the topology list.
 *
 * This function initializes the topology list state.
 *
 * \param list The topology list state to initialize.
 */
MPDC_EXPORT_API void mpdc_topology_list_initialize(mpdc_topology_list_state* list);

/**
 * \brief Get a node from the index.
 *
 * This function retrieves the node at the specified index in the topology list.
 *
 * \param list The topology list state.
 * \param node A pointer to the node structure to populate.
 * \param index The index of the node.
 * \return Returns false if the node was not found.
 */
MPDC_EXPORT_API bool mpdc_topology_list_item(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, size_t index);

/**
 * \brief Remove duplicate nodes from the topology.
 *
 * This function removes duplicate entries from the topology list.
 *
 * \param list The topology list state.
 * \return Returns the number of items remaining in the list.
 */
MPDC_EXPORT_API size_t mpdc_topology_list_remove_duplicates(mpdc_topology_list_state* list);

/**
 * \brief Get the count of a type of node in the database.
 *
 * This function counts the number of nodes of a specific type in the topology list.
 *
 * \param list [const] The topology list state.
 * \param ntype The type of node entry to count.
 * \return Returns the number of nodes matching the given type.
 */
MPDC_EXPORT_API size_t mpdc_topology_list_server_count(const mpdc_topology_list_state* list, mpdc_network_designations ntype);

/**
 * \brief Serialize a topology list.
 *
 * This function serializes the topology list into a byte array.
 *
 * \param output The output buffer for the serialized topology.
 * \param list [const] The topology list state.
 * \return Returns the size of the serialized topology.
 */
MPDC_EXPORT_API size_t mpdc_topology_list_serialize(uint8_t* output, const mpdc_topology_list_state* list);

/**
 * \brief Get the byte size of the serialized list.
 *
 * This function returns the size in bytes of the serialized topology list.
 *
 * \param list [const] The topology list state.
 * \return Returns the byte size of the serialized topology.
 */
MPDC_EXPORT_API size_t mpdc_topology_list_size(const mpdc_topology_list_state* list);

/**
 * \brief Convert the topology list to a printable string.
 *
 * This function converts the topology list into a human?readable string.
 *
 * \param list [const] The topology list state.
 * \param output The output string buffer.
 * \param outlen The length of the output buffer.
 * \return Returns the size of the resulting string.
 */
MPDC_EXPORT_API size_t mpdc_topology_list_to_string(const mpdc_topology_list_state* list, char* output, size_t outlen);

/**
 * \brief Pack a node update set to an array.
 *
 * This function serializes a subset of nodes from the topology list (of a given type) into an array.
 *
 * \param output The output buffer for the serialized node update set.
 * \param list [const] The topology list state.
 * \param ntype The type of node entry to pack.
 * \return Returns the size of the serialized node update set.
 */
MPDC_EXPORT_API size_t mpdc_topology_list_update_pack(uint8_t* output, const mpdc_topology_list_state* list, mpdc_network_designations ntype);

/**
 * \brief Unpack a node update set to the topology list.
 *
 * This function deserializes an update set and adds the nodes to the topology list.
 *
 * \param list The topology list state to update.
 * \param input The input serialized node update set.
 * \param inplen The length of the input array.
 * \return Returns the number of bytes processed.
 */
MPDC_EXPORT_API size_t mpdc_topology_list_update_unpack(mpdc_topology_list_state* list, const uint8_t* input, size_t inplen);

/**
 * \brief Return a list of nodes of a type, sorted by serial number.
 *
 * This function returns a new topology list containing nodes of a specific type, sorted by their serial number.
 * \note The caller is responsible for disposing the output list.
 *
 * \param olist The sorted output topology list.
 * \param tlist The unsorted input topology list.
 * \param ntype The type of node to filter and sort.
 * \return Returns the number of nodes in the sorted list.
 */
MPDC_EXPORT_API size_t mpdc_topology_ordered_server_list(mpdc_topology_list_state* olist, const mpdc_topology_list_state* tlist, mpdc_network_designations ntype);

/**
 * \brief Erase a node structure.
 *
 * This function clears all data in a topology node structure.
 *
 * \param node A pointer to the topology node structure to erase.
 */
MPDC_EXPORT_API void mpdc_topology_node_clear(mpdc_topology_node_state* node);

/**
 * \brief Copy a source node to a destination node structure.
 *
 * This function copies the contents of one topology node structure to another.
 *
 * \param source [const] A pointer to the source node structure.
 * \param destination A pointer to the destination node structure.
 */
MPDC_EXPORT_API void mpdc_topology_node_copy(const mpdc_topology_node_state* source, mpdc_topology_node_state* destination);

/**
 * \brief Deserialize a topological node.
 *
 * This function converts a serialized topology node array into a topology node structure.
 *
 * \param node A pointer to the topology node structure to populate.
 * \param input [const] The input serialized topology node data.
 */
MPDC_EXPORT_API void mpdc_topology_node_deserialize(mpdc_topology_node_state* node, const uint8_t* input);

/**
 * \brief Encode a topological node into a printable string.
 *
 * This function encodes a topology node into a human?readable string format.
 *
 * \param node A pointer to the topology node structure.
 * \param output The output buffer for the encoded node string.
 * \return Returns the size of the encoded node string.
 */
MPDC_EXPORT_API size_t mpdc_topology_node_encode(const mpdc_topology_node_state* node, char output[MPDC_TOPOLOGY_NODE_ENCODED_SIZE]);

/**
 * \brief Queries on the serial number if the node is in the database.
 *
 * This function checks whether a node with the specified serial number exists in the topology list.
 *
 * \param list [const] The topology list state.
 * \param serial The serial number to search for.
 * \return Returns true if the node exists; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_exists(const mpdc_topology_list_state* list, const uint8_t* serial);

/**
 * \brief Find the index number of a node in an array.
 *
 * This function searches for a node by its serial number and returns its index in the topology list.
 *
 * \param list [const] The topology list state.
 * \param serial The serial number to search for.
 * \return Returns the index of the node, or MPDC_TOPOLOGY_NODE_NOT_FOUND if not found.
 */
MPDC_EXPORT_API int32_t mpdc_topology_node_get_index(const mpdc_topology_list_state* list, const uint8_t* serial);

/**
 * \brief Return the node pointer in the list matching the serial number.
 *
 * This function finds a node in the topology list that matches the given serial number.
 *
 * \param list [const] The topology list state.
 * \param node A pointer to the destination node structure to populate.
 * \param serial [const] The certificate serial number to search for.
 * \return Returns true if the node was found; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_find(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const uint8_t* serial);

/**
 * \brief Return the node pointer in the list matching the address string.
 *
 * This function searches the topology list for a node that matches the given network address.
 *
 * \param list [const] The topology list state.
 * \param node A pointer to the destination node structure.
 * \param address [const] The network address to search for.
 * \return Returns true if the node was found; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_find_address(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const char* address);

/**
 * \brief Return the node pointer in the list matching the alias string.
 *
 * This function searches the topology list for a node that matches the given alias.
 *
 * \param list [const] The topology list state.
 * \param node A pointer to the destination node structure.
 * \param alias [const] The alias to search for.
 * \return Returns true if the node was found; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_find_alias(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const char* alias);

/**
 * \brief Return the DLA node from the list.
 *
 * This function finds the DLA node in the topology list.
 *
 * \param list [const] The topology list state.
 * \param node A pointer to the destination node structure.
 * \return Returns true if the DLA node was found; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_find_dla(const mpdc_topology_list_state* list, mpdc_topology_node_state* node);

/**
 * \brief Return the node pointer in the list matching the name string.
 *
 * This function finds a node in the topology list that matches the given issuer name.
 *
 * \param list [const] The topology list state.
 * \param node A pointer to the destination node structure.
 * \param issuer [const] The certificate issuer name.
 * \return Returns true if the node was found; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_find_issuer(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const char* issuer);

/**
 * \brief Return the RDS server node from the list.
 *
 * This function retrieves the RDS server node from the topology list.
 *
 * \param list [const] The topology list state.
 * \param node A pointer to the destination node structure.
 * \return Returns true if the RDS server node was found; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_find_root(const mpdc_topology_list_state* list, mpdc_topology_node_state* node);

/**
 * \brief Find and remove a node from the topology.
 *
 * This function searches for a node by its serial number and removes it from the topology list.
 *
 * \param list The topology list state.
 * \param serial The serial number of the node to remove (MPDC_CERTIFICATE_SERIAL_SIZE bytes).
 */
MPDC_EXPORT_API void mpdc_topology_node_remove(mpdc_topology_list_state* list, const uint8_t* serial);

/**
 * \brief Remove a node from the topology with the same issuer name.
 *
 * This function removes duplicate nodes from the topology list that have the same issuer name.
 *
 * \param list The topology list state.
 * \param issuer The issuer name to match for removal.
 */
MPDC_EXPORT_API void mpdc_topology_node_remove_duplicate(mpdc_topology_list_state* list, const char* issuer);

/**
 * \brief Verify that the DLA certificate matches the hash stored in the topology.
 *
 * This function verifies that the DLA certificate in the topology list matches the certificate hash.
 *
 * \param list [const] The topology list state.
 * \param ccert [const] The DLA certificate structure.
 * \return Returns true if the certificate matches the stored hash; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_verify_dla(const mpdc_topology_list_state* list, const mpdc_child_certificate* ccert);

/**
 * \brief Verify that an issuing node's certificate matches the hash stored in the topology.
 *
 * This function verifies that the certificate for a given issuer matches the stored hash in the topology list.
 *
 * \param list [const] The topology list state.
 * \param ccert [const] The node's certificate structure.
 * \param issuer [const] The certificate issuer name.
 * \return Returns true if the certificate is valid and matches; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_verify_issuer(const mpdc_topology_list_state* list, const mpdc_child_certificate* ccert, const char* issuer);

/**
 * \brief Verify that the root certificate matches the hash stored in the topology.
 *
 * This function verifies that the root certificate matches the hash stored in the topology list.
 *
 * \param list [const] The topology list state.
 * \param rcert [const] The root certificate structure.
 * \return Returns true if the root certificate is valid; false otherwise.
 */
MPDC_EXPORT_API bool mpdc_topology_node_verify_root(const mpdc_topology_list_state* list, const mpdc_root_certificate* rcert);

/**
 * \brief Serialize a topological node structure, including the mfk.
 *
 * This function serializes the topology node structure into a byte array.
 *
 * \param output The output buffer to receive the serialized node.
 * \param node [const] A pointer to the topology node structure.
 * \return Returns the size of the serialized node.
 */
MPDC_EXPORT_API size_t mpdc_topology_node_serialize(uint8_t* output, const mpdc_topology_node_state* node);

/**
 * \brief Register a root to a topology list.
 *
 * This function registers a root certificate into the topology list.
 *
 * \param list A pointer to the topology list.
 * \param rcert [const] The root certificate.
 * \param address [const] The network address of the root.
 */
MPDC_EXPORT_API void mpdc_topology_root_register(mpdc_topology_list_state* list, const mpdc_root_certificate* rcert, const char* address);

/**
 * \brief Copy a topology list from a file.
 *
 * This function loads a topology list from a file.
 *
 * \param fpath [const] The full path to the topology list file.
 * \param list A pointer to the topology list state to populate.
 */
MPDC_EXPORT_API void mpdc_topology_from_file(const char* fpath, mpdc_topology_list_state* list);

/**
 * \brief Copy a topology list to a file.
 *
 * This function writes the current topology list to a file.
 *
 * \param list [const] The topology list state.
 * \param fpath [const] The destination file path for the topology list.
 */
MPDC_EXPORT_API void mpdc_topology_to_file(const mpdc_topology_list_state* list, const char* fpath);

#if defined(QSC_DEBUG_MODE)
/**
 * \brief Test the topology functions.
 *
 * This function runs a series of tests on the topology functions.
 *
 * \return Returns true if all tests pass.
 */
MPDC_EXPORT_API bool mpdc_topology_functions_test();
#endif

#endif
