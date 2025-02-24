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


/**
* \file idg.h
* \brief The MPDC Inter Domain Gateway server
*/

/* Notes: 
* IDG servers exchange root certificates with other networks/domains.
* The IDG certificate has a field that contains an external signature.
* This is the signed hash of the IDG certificate signed by an external certificate authority, 
* which can be an X509 certificate, allowing the domains root certificate to attain an initial
* trust score, while building the MPDC external trust heirarchy.
* Established IDG peers exchange hints about their associations, that can be exchanged to cross populate peer databases, 
* and contribute to the trust value calculation of each node in the database.
* A reursive query sends the hint to external peers, which either answer if the remote IDG certificate is known,
* or query their view of trusted IDG peers in their database. 
* The root (RDS) signature (which signs server certificates within the remote domain), is signed by the IDG,
* and the IDG certificate can be signed by an external X509 certificate authority.
* 
* 
* 
* 
* 
* 
* EXT-IDG<->IDG->RDS->(Agent,Server)
* IDG certificate
* 
*/

#ifndef MPDC_IDG_H
#define MPDC_IDG_H

#include "common.h"




#endif