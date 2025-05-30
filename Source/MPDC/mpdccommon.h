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

#ifndef MPDC_COMMON_H
#define MPDC_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "qsccommon.h"

/**
* \internal
* \file common.h
* \brief The MPDC common includes
*/

/*!
* \def MPDC_CONFIG_DILITHIUM_KYBER
* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/Kyber.
*/
#define MPDC_CONFIG_DILITHIUM_KYBER

/*!
* \def MPDC_CONFIG_SPHINCS_MCELIECE
* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece, default is Dilithium/Kyber.
* Note: You may have to increase the stack reserve size on both projects, McEliece and Sphincs+ use a lot of resources.
*/
#if !defined(MPDC_CONFIG_DILITHIUM_KYBER)
#	define MPDC_CONFIG_SPHINCS_MCELIECE
#endif

#if defined(DEBUG) || defined(_DEBUG) || defined(__DEBUG__) || (defined(__GNUC__) && !defined(__OPTIMIZE__))
/*!
\def MPDC_COMPILE_DEBUG_MODE
* \brief The build is in bebug mode
*/
#	define MPDC_COMPILE_DEBUG_MODE
#endif

/*!
\def MPDC_DEBUG_TESTS_RUN
* \brief run the internal function tests
*/
#if defined(MPDC_COMPILE_DEBUG_MODE)
//#	define MPDC_DEBUG_TESTS_RUN
#endif

/* application constants */
#define MPDC_CRYPTO_PASSWORD_HASH 32
#define MPDC_DEFAULT_AUTH_RETRIES 3
#define MPDC_DEFAULT_PORT 8022
#define MPDC_DEFAULT_SESSION_TIMEOUT 5
#define MPDC_STORAGE_ADDRESS_MIN 7
#define MPDC_STORAGE_ADDRESS_MAX 65
#define MPDC_STORAGE_ASSOCIATION_HOSTS_MAX 16
#define MPDC_STORAGE_CERTIFICATE_NAME 128
#define MPDC_STORAGE_DEVICENAME_MAX 16
#define MPDC_STORAGE_DEVICENAME_MIN 2
#define MPDC_STORAGE_DOMAINNAME_MAX 260
#define MPDC_STORAGE_DOMAINNAME_MIN 2
#define MPDC_STORAGE_FILEPATH_MAX 256
#define MPDC_STORAGE_FILEPATH_MIN 8
#define MPDC_STORAGE_HOSTNAME_MIN 2
#define MPDC_STORAGE_HOSTNAME_MAX 128
#define MPDC_STORAGE_INPUT_MAX 256
#define MPDC_STORAGE_MAC_SIZE 32
#define MPDC_STORAGE_MAX_PATH 260
#define MPDC_STORAGE_MESSAGE_MAX 8192
#define MPDC_STORAGE_PASSWORD_MAX 256
#define MPDC_STORAGE_PASSWORD_MIN 8
#define MPDC_STORAGE_PASSWORD_RETRY 3
#define MPDC_STORAGE_PATH_MAX 260
#define MPDC_STORAGE_PROMPT_MAX 64
#define MPDC_STORAGE_RETRIES_MIN 1
#define MPDC_STORAGE_RETRIES_MAX 5
#define MPDC_STORAGE_SERVER_PAUSE_INTERVAL 250
#define MPDC_STORAGE_TIMEOUT_MIN 1
#define MPDC_STORAGE_TIMEOUT_MAX 60
#define MPDC_STORAGE_USERNAME_MAX 128
#define MPDC_STORAGE_USERNAME_MIN 6
#define MPDC_STORAGE_USERNAME_RETRY 3

/*!
\def MPDC_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define MPDC_DLL_API
#endif

/*!
\def MPDC_EXPORT_API
* \brief The api export prefix
*/
#if defined(MPDC_DLL_API)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		if defined(MPDC_DLL_IMPORT)
#			define MPDC_EXPORT_API __declspec(dllimport)
#		else
#			define MPDC_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		if defined(MPDC_DLL_IMPORT)
#		define MPDC_EXPORT_API __attribute__((dllimport))
#		else
#		define MPDC_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define MPDC_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define MPDC_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define MPDC_EXPORT_API extern __declspec(dllexport)
#		else
#			define MPDC_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define MPDC_EXPORT_API
#endif

static const char MPDC_DEFAULT_APP_PATH[] = "C:\\";
static const char MPDC_LOG_FILENAME[] = "\\userlog.mlog";

#endif