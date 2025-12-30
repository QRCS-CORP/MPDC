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
