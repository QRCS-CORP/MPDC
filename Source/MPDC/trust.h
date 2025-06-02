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

#ifndef MPDC_TRUST_H
#define MPDC_TRUST_H

#include "mpdc.h"
#include "intutils.h"
#include "memutils.h"

/**
 * \file trust.h
 * \brief The MPDC trust functions.
 *
 * Detailed Description:
 * This header file declares the functions and data structures used to manage device trust within the
 * MPDC system. Trust data is used to store network-related information (address, domain, name) along with
 * associated metrics such as trust value, bandwidth, and flags indicating IPv6 support and local network status.
 * The functions provided herein allow for the serialization and deserialization of trust data, as well as clearing
 * a trust record.
 */

/*! 
 * \def MPDC_TRUST_SIZE
 * \brief The size of a device trust structure.
 *
 * This macro returns the size in bytes of the MPDC device trust structure.
 */
#define MPDC_TRUST_SIZE (sizeof(mpdc_device_trust))

/*!
 * \struct mpdc_device_trust
 * \brief The MPDC topology device trust structure.
 *
 * This structure contains trust-related information for a network device. It includes the device's network address,
 * domain, name, trust value, bandwidth metric, and flags to indicate IPv6 capability and whether the device is on the local network.
 */
MPDC_EXPORT_API typedef struct mpdc_device_trust
{
    char address[MPDC_DLA_IP_MAX];                 /*!< The device address */
    char domain[MPDC_NETWORK_DOMAIN_NAME_MAX_SIZE];  /*!< The device domain name */
    char name[MPDC_AGENT_NAME_MAX_SIZE];            /*!< The device name */
    uint64_t dtrust;                                /*!< The device trust value */
    uint32_t bandwidth;                             /*!< The bandwidth metric */
    bool isipv6;                                    /*!< True if the device supports IPv6 */
    bool local;                                     /*!< True if the device is on the local network */
} mpdc_device_trust;

/**
 * \brief Remove a device trust from the database.
 *
 * This function clears all trust data in a given device trust structure.
 *
 * \param device A pointer to the device trust structure to clear.
 */
MPDC_EXPORT_API void mpdc_trust_clear(mpdc_device_trust* device);

/**
 * \brief Deserialize a device trust structure.
 *
 * This function converts a serialized device trust byte array into a \c mpdc_device_trust structure.
 *
 * \param device A pointer to the output device trust structure.
 * \param input [const] The serialized trust structure data.
 */
MPDC_EXPORT_API void mpdc_trust_deserialize(mpdc_device_trust* device, const uint8_t* input);

/**
 * \brief Serialize a device trust structure.
 *
 * This function serializes a \c mpdc_device_trust structure into a byte array.
 *
 * \param output The output buffer to receive the serialized data.
 * \param outlen The length of the output buffer.
 * \param device [const] A pointer to the device trust structure to serialize.
 */
MPDC_EXPORT_API void mpdc_trust_serialize(uint8_t* output, size_t outlen, const mpdc_device_trust* device);

#endif
