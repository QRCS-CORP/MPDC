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

#ifndef MPDC_MPDC_H
#define MPDC_MPDC_H

#include "common.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/socketbase.h"

#if defined(MPDC_CONFIG_DILITHIUM_KYBER)
#	include "../../QSC/QSC/dilithium.h"
#	include "../../QSC/QSC/kyber.h"
#elif defined(MPDC_CONFIG_SPHINCS_MCELIECE)
#	include "../../QSC/QSC/mceliece.h"
#	include "../../QSC/QSC/sphincsplus.h"
#else
#	error Invalid parameter set!
#endif

/**
 * \file mpdc.h
 * \brief MPDC Common Definitions and Protocol Configuration.
 *
 * \details
 * This header defines the common constants, macros, enumerations, structures, and function prototypes
 * for the Multi-Party Domain Cryptosystem (MPDC). It provides configuration for the cryptographic parameter sets,
 * certificate handling, network protocol operations, and socket communication required to implement the MPDC protocol.
 *
 * The MPDC protocol leverages a combination of asymmetric cipher and signature schemes from the QSC library.
 * The parameter sets can be configured in the QSC library's common.h file. For maximum security, the McEliece/SPHINCS+
 * parameter set is recommended; for a balance of performance and security, the Dilithium/Kyber parameter set is advised.
 *
 * Key components defined in this header include:
 * - **Function Mapping Macros:** Aliases that map MPDC high-level cryptographic operations (key generation,
 *   encapsulation/decapsulation, signing, and verification) to the corresponding functions in the QSC library,
 *   based on the selected configuration.
 * - **Modifiable Constants:** Preprocessor definitions that enable or disable protocol features (e.g., client-to-client
 *   encrypted tunneling, master fragment key cycling, IPv6 networking, and extended session security).
 * - **Parameter Macros:** Definitions for key sizes, certificate field sizes, network settings, and timing values that ensure
 *   consistency across the MPDC protocol implementation.
 * - **Enumerations:** Enumerated types for MPDC configuration sets, network designations, network and protocol error codes,
 *   and version sets.
 * - **Structures:** Data structures representing various certificates (child, IDG, root), connection and keep alive states,
 *   network packets, and cryptographic key pairs. These structures are central to protocol operations such as certificate
 *   management and secure message exchange.
 * - **Static Constants:** Predefined strings for certificate header/footer information and network designation labels.
 * - **Public API Functions:** Prototypes for functions handling connection management, packet encryption/decryption,
 *   packet serialization/deserialization, and error string conversion.
 *
 * \note
 * When using the McEliece/SPHINCS+ configuration in Visual Studio, it is recommended to increase the maximum stack size
 * (for example, to 200KB) to accommodate the larger key sizes.
 *
 * \test
 * Although this header does not directly implement test routines, it underpins multiple test modules that validate:
 * - The correct mapping of MPDC high-level function calls to the underlying QSC library routines.
 * - The consistency and accuracy of defined constants (e.g., key sizes, certificate sizes, network parameters).
 * - The proper serialization/deserialization of packet headers and full packets (via mpdc_packet_header_serialize and
 *   mpdc_stream_to_packet).
 * - The correct conversion of error codes to descriptive strings (using mpdc_network_error_to_string and
 *   mpdc_protocol_error_to_string).
 *
 * These tests collectively ensure the robustness, consistency, and security of the MPDC protocol configuration.
 */

/* --- Function Mapping Macros --- */

/*!
* \def MPDC_USE_RCS_ENCRYPTION
* \brief If the RCS encryption option is chosen SKDP uses the more modern RCS stream cipher with KMAC/QMAC authentication.
* The default symmetric cipher/authenticator is AES-256/GCM (GMAC Counter Mode) NIST standardized per SP800-38a.
*/
//#define MPDC_USE_RCS_ENCRYPTION

#if defined(MPDC_USE_RCS_ENCRYPTION)
#	include "../../QSC/QSC/rcs.h"
#	define mpdc_cipher_state qsc_rcs_state
#	define mpdc_cipher_dispose qsc_rcs_dispose
#	define mpdc_cipher_initialize qsc_rcs_initialize
#	define mpdc_cipher_keyparams qsc_rcs_keyparams
#	define mpdc_cipher_set_associated qsc_rcs_set_associated
#	define mpdc_cipher_transform qsc_rcs_transform
#else
#	include "../../QSC/QSC/aes.h"
#	define mpdc_cipher_state qsc_aes_gcm256_state
#	define mpdc_cipher_dispose qsc_aes_gcm256_dispose
#	define mpdc_cipher_initialize qsc_aes_gcm256_initialize
#	define mpdc_cipher_keyparams qsc_aes_keyparams
#	define mpdc_cipher_set_associated qsc_aes_gcm256_set_associated
#	define mpdc_cipher_transform qsc_aes_gcm256_transform
#endif

/**
 * \brief MPDC function mapping macros.
 *
 * These macros alias the high-level MPDC cryptographic operations to the corresponding QSC library functions.
 * The mapping depends on the selected parameter set. For instance, if MPDC_CONFIG_SPHINCS_MCELIECE is defined,
 * then the MPDC cipher and signature functions map to the McEliece/SPHINCS+ routines. Alternatively, if
 * MPDC_CONFIG_DILITHIUM_KYBER is defined, the corresponding Dilithium/Kyber routines are used.
 */
#if defined(MPDC_CONFIG_SPHINCS_MCELIECE)
/*!
 * \def mpdc_cipher_generate_keypair
 * \brief Generate an asymmetric cipher key-pair
 */
#	define mpdc_cipher_generate_keypair qsc_mceliece_generate_keypair
/*!
 * \def mpdc_cipher_decapsulate
 * \brief Decapsulate a shared-secret with the asymmetric cipher
 */
#	define mpdc_cipher_decapsulate qsc_mceliece_decapsulate
/*!
 * \def mpdc_cipher_encapsulate
 * \brief Encapsulate a shared-secret with the asymmetric cipher
 */
#	define mpdc_cipher_encapsulate qsc_mceliece_encapsulate
/*!
 * \def mpdc_signature_generate_keypair
 * \brief Generate an asymmetric signature key-pair
 */
#	define mpdc_signature_generate_keypair qsc_sphincsplus_generate_keypair
/*!
 * \def mpdc_signature_sign
 * \brief Sign a message with the asymmetric signature scheme
 */
#	define mpdc_signature_sign qsc_sphincsplus_sign
/*!
 * \def mpdc_signature_verify
 * \brief Verify a message with the asymmetric signature scheme
 */
#	define mpdc_signature_verify qsc_sphincsplus_verify
#elif defined(MPDC_CONFIG_DILITHIUM_KYBER)
/*!
 * \def mpdc_cipher_generate_keypair
 * \brief Generate an asymmetric cipher key-pair
 */
#	define mpdc_cipher_generate_keypair qsc_kyber_generate_keypair
/*!
 * \def mpdc_cipher_decapsulate
 * \brief Decapsulate a shared-secret with the asymmetric cipher
 */
#	define mpdc_cipher_decapsulate qsc_kyber_decapsulate
/*!
 * \def mpdc_cipher_encapsulate
 * \brief Encapsulate a shared-secret with the asymmetric cipher
 */
#	define mpdc_cipher_encapsulate qsc_kyber_encapsulate
/*!
 * \def mpdc_signature_generate_keypair
 * \brief Generate an asymmetric signature key-pair
 */
#	define mpdc_signature_generate_keypair qsc_dilithium_generate_keypair
/*!
 * \def mpdc_signature_sign
 * \brief Sign a message with the asymmetric signature scheme
 */
#	define mpdc_signature_sign qsc_dilithium_sign
/*!
 * \def mpdc_signature_verify
 * \brief Verify a message with the asymmetric signature scheme
 */
#	define mpdc_signature_verify qsc_dilithium_verify
#else
#	error Invalid parameter set!
#endif

/* ### Modifiable Constants: These constants can be enabled to turn on protocol features ### */

///*!
// * \def MPDC_NETWORK_CLIENT_CONNECT
// * \brief Enable client to client encrypted tunnel.
// */
//#define MPDC_NETWORK_CLIENT_CONNECT

///*!
// * \def MPDC_NETWORK_MFK_HASH_CYCLED
// * \brief Enable mfk key cycling (default).
// */
//#define MPDC_NETWORK_MFK_HASH_CYCLED

/*!
 * \def MPDC_NETWORK_PROTOCOL_IPV6
 * \brief MPDC is using the IPv6 networking stack.
 */
//#define MPDC_NETWORK_PROTOCOL_IPV6

///*!
// * \def MPDC_EXTENDED_SESSION_SECURITY
// * \brief Enable 512-bit security on session tunnels.
// */
//#define MPDC_EXTENDED_SESSION_SECURITY

/* ### End of Modifiable Constants ### */


#if defined(MPDC_CONFIG_DILITHIUM_KYBER)

/*!
 * \def MPDC_ASYMMETRIC_CIPHERTEXT_SIZE
 * \brief The byte size of the asymmetric cipher-text array.
 */
#	define MPDC_ASYMMETRIC_CIPHERTEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_PRIVATE_KEY_SIZE
 * \brief The byte size of the asymmetric cipher private-key array.
 */
#	define MPDC_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE
 * \brief The byte size of the asymmetric cipher public-key array.
 */
#	define MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_SIGNATURE_SIZE
 * \brief The byte size of the asymmetric signature array.
 */
#	define MPDC_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_SIGNING_KEY_SIZE
 * \brief The byte size of the asymmetric signature signing-key array.
 */
#	define MPDC_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE
 * \brief The byte size of the asymmetric signature verification-key array.
 */
#	define MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

#	if defined(QSC_DILITHIUM_S1P2544) && defined(QSC_KYBER_S1P1632)
/*!
 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define MPDC_CHILD_CERTIFICATE_STRING_SIZE 5612
/*!
 * \def MPDC_PARAMATERS_DILITHIUM_KYBER_D1K1
 * \brief The Dilithium D1K1 parameter set
 */
#		define MPDC_PARAMATERS_DILITHIUM_KYBER_D1K1
/*!
 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define MPDC_ROOT_CERTIFICATE_STRING_SIZE 2188
/*!
 * \def MPDC_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define MPDC_SIGNATURE_ENCODING_SIZE 3312
/*!
 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define MPDC_VERIFICATION_KEY_ENCODING_SIZE 1752
#	elif defined(QSC_DILITHIUM_S3P4016) && defined(QSC_KYBER_S3P2400)
/*!
 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define MPDC_CHILD_CERTIFICATE_STRING_SIZE 7648
/*!
 * \def MPDC_PARAMATERS_DILITHIUM_KYBER_D3K3
 * \brief The Dilithium D1K1 parameter set
 */
#		define MPDC_PARAMATERS_DILITHIUM_KYBER_D3K3
/*!
 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define MPDC_ROOT_CERTIFICATE_STRING_SIZE 3053
/*!
 * \def MPDC_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define MPDC_SIGNATURE_ENCODING_SIZE 4476
/*!
 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define MPDC_VERIFICATION_KEY_ENCODING_SIZE 2604
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_KYBER_S5P3168)
/*!
 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define MPDC_CHILD_CERTIFICATE_STRING_SIZE 10311
/*!
 * \def MPDC_PARAMATERS_DILITHIUM_KYBER_D5K5
 * \brief The Dilithium D1K1 parameter set
 */
#		define MPDC_PARAMATERS_DILITHIUM_KYBER_D5K5
/*!
 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define MPDC_ROOT_CERTIFICATE_STRING_SIZE 3919
/*!
 * \def MPDC_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define MPDC_SIGNATURE_ENCODING_SIZE 6212
/*!
 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define MPDC_VERIFICATION_KEY_ENCODING_SIZE 3456
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_KYBER_S6P3936)
/*!
 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define MPDC_CHILD_CERTIFICATE_STRING_SIZE 10311
/*!
 * \def MPDC_PARAMATERS_DILITHIUM_KYBER_D5K6
 * \brief The Dilithium D1K1 parameter set
 */
#		define MPDC_PARAMATERS_DILITHIUM_KYBER_D5K6
/*!
 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define MPDC_ROOT_CERTIFICATE_STRING_SIZE 3919
/*!
 * \def MPDC_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define MPDC_SIGNATURE_ENCODING_SIZE 6172
/*!
 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define MPDC_VERIFICATION_KEY_ENCODING_SIZE 3456
#	else
		/* The library signature scheme and asymmetric cipher parameter sets 
		must be synchronized to a common security level; s1, s3, s5, s5+ */
#		error the library parameter sets are mismatched!
#	endif

#elif defined(MPDC_CONFIG_SPHINCS_MCELIECE)

/*!
 * \def MPDC_ASYMMETRIC_CIPHERTEXT_SIZE
 * \brief The byte size of the cipher-text array.
 */
#	define MPDC_ASYMMETRIC_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_PRIVATE_KEY_SIZE
 * \brief The byte size of the asymmetric cipher private-key array.
 */
#	define MPDC_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE
 * \brief The byte size of the asymmetric cipher public-key array.
 */
#	define MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_SIGNATURE_SIZE
 * \brief The byte size of the asymmetric signature array.
 */
#	define MPDC_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_SIGNING_KEY_SIZE
 * \brief The byte size of the asymmetric signature signing-key array.
 */
#	define MPDC_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
 * \def MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE
 * \brief The byte size of the asymmetric signature verification-key array.
 */
#	define MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

#	if defined(QSC_MCELIECE_S1N3488T64)
#		if defined(QSC_SPHINCSPLUS_S1S128SHAKERF)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 23737
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SF1M1
			 * \brief The McEliece SF1M1 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF1M1
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 455
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 22828
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 44
#		elif defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 11237
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SS1M1
			 * \brief The McEliece SS1M1 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSS_MCELIECE_SS1M1
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 455
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 10520
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 44
#		endif
#	elif defined(QSC_MCELIECE_S3N4608T96)
#		if defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 48912
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SF3M3
			 * \brief The McEliece SF3M3 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF3M3
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 476
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 47596
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 64
#		elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 22588
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SS3M3
			 * \brief The McEliece SS3M3 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSS_MCELIECE_SS3M3
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 476
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 21676
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 64
#		endif
#	elif defined(QSC_MCELIECE_S5N6688T128)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 68158
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SF5M5
			 * \brief The McEliece SF5M5 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF5M5
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 501
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 66520
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 88
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 40987
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SS5M5
			 * \brief The McEliece SS5M5 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSS_MCELIECE_SS5M5
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 501
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 39768
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 88
#		endif
#	elif defined(QSC_MCELIECE_S6N6960T119)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 68157
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SF5M6
			 * \brief The McEliece SF5M6 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF5M6
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 501
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 66520
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 88
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 40987
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SS5M6
			 * \brief The McEliece SS5M6 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSS_MCELIECE_SS5M6
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 501
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 39768
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 88
#		endif
#	elif defined(QSC_MCELIECE_S7N8192T128)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 68157
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SF5M7
			 * \brief The McEliece SF5M7 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF5M7
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 501
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 66520
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 88
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			 * \def MPDC_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define MPDC_CHILD_CERTIFICATE_STRING_SIZE 40987
			/*!
			 * \def MPDC_PARAMATERS_MCELIECE_SS5M7
			 * \brief The McEliece SS5M7 parameter set
			 */
#			define MPDC_PARAMATERS_SPHINCSS_MCELIECE_SS5M7
			/*!
			 * \def MPDC_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define MPDC_ROOT_CERTIFICATE_STRING_SIZE 501
			/*!
			 * \def MPDC_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define MPDC_SIGNATURE_ENCODING_SIZE 39768
			/*!
			 * \def MPDC_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define MPDC_VERIFICATION_KEY_ENCODING_SIZE 88
#		else
#			error Invalid parameter sets, check the QSC library settings 
#		endif
#	else
	/* The library signature scheme and asymmetric cipher parameter sets 
	must be synchronized to a common security level; s1, s3, s5 or s6.
	Check the QSC library common.h file for cipher and signature security level alignment. */
#	error Invalid parameter sets, check the QSC library settings 
#	endif
#endif

/*!
 * \def MPDC_ACTIVE_VERSION
 * \brief The MPDC active version.
 */
#define MPDC_ACTIVE_VERSION 1

/*!
 * \def MPDC_ACTIVE_VERSION_SIZE
 * \brief The MPDC active version size.
 */
#define MPDC_ACTIVE_VERSION_SIZE 2

/*!
 * \def MPDC_APPLICATION_AGENT_PORT
 * \brief The default Agent port number.
 */
#define MPDC_APPLICATION_AGENT_PORT 37766

/*!
 * \def MPDC_AGENT_FULL_TRUST
 * \brief The full trust designation number.
 */
#define MPDC_AGENT_FULL_TRUST 1000001

/*!
 * \def MPDC_AGENT_MINIMUM_TRUST
 * \brief The minimum trust designation number.
 */
#define MPDC_AGENT_MINIMUM_TRUST 1

/*!
 * \def MPDC_AGENT_NAME_MAX_SIZE
 * \brief The maximum agent name string length in characters.
 * The last character must be a string terminator.
 */
#define MPDC_AGENT_NAME_MAX_SIZE 256

/*!
 * \def MPDC_AGENT_TWOWAY_TRUST
 * \brief The two-way trust designation number.
 */
#define MPDC_AGENT_TWOWAY_TRUST 1000002

/*!
 * \def MPDC_APPLICATION_CLIENT_PORT
 * \brief The default MPDC Client port number.
 */
#define MPDC_APPLICATION_CLIENT_PORT 37761

/*!
 * \def MPDC_APPLICATION_DLA_PORT
 * \brief The default DLA port number.
 */
#define MPDC_APPLICATION_DLA_PORT 37762

/*!
 * \def MPDC_APPLICATION_IDG_PORT
 * \brief The default MPDC IDG port number.
 */
#define MPDC_APPLICATION_IDG_PORT 37763

/*!
 * \def MPDC_APPLICATION_RDS_PORT
 * \brief The default RDS port number.
 */
#define MPDC_APPLICATION_RDS_PORT 37764

/*!
 * \def MPDC_APPLICATION_MAS_PORT
 * \brief The default MPDC MAS port number.
 */
#define MPDC_APPLICATION_MAS_PORT 37765

/*!
 * \def MPDC_CANONICAL_NAME_MINIMUM_SIZE
 * \brief The minimum canonical name size.
 */
#define MPDC_CANONICAL_NAME_MINIMUM_SIZE 3

/*!
 * \def MPDC_CERTIFICATE_ADDRESS_SIZE
 * \brief The maximum IP address length.
 */
#define MPDC_CERTIFICATE_ADDRESS_SIZE 22

/*!
 * \def MPDC_CERTIFICATE_ALGORITHM_SIZE
 * \brief The algorithm type.
 */
#define MPDC_CERTIFICATE_ALGORITHM_SIZE 1

/*!
 * \def MPDC_CERTIFICATE_DEFAULT_PERIOD
 * \brief The default certificate validity period in milliseconds.
 */
#define MPDC_CERTIFICATE_DEFAULT_PERIOD ((uint64_t)365 * 24 * 60 * 60)

/*!
 * \def MPDC_CERTIFICATE_DESIGNATION_SIZE
 * \brief The size of the child certificate designation field.
 */
#define MPDC_CERTIFICATE_DESIGNATION_SIZE 1

/*!
 * \def MPDC_CERTIFICATE_EXPIRATION_SIZE
 * \brief The certificate expiration date length.
 */
#define MPDC_CERTIFICATE_EXPIRATION_SIZE 16

/*!
 * \def MPDC_CERTIFICATE_HASH_SIZE
 * \brief The size of the certificate hash in bytes.
 */
#define MPDC_CERTIFICATE_HASH_SIZE 32

/*!
 * \def MPDC_CERTIFICATE_ISSUER_SIZE
 * \brief The maximum certificate issuer string length.
 * The last character must be a string terminator.
 */
#define MPDC_CERTIFICATE_ISSUER_SIZE 256

/*!
 * \def MPDC_CERTIFICATE_LINE_LENGTH
 * \brief The line length of the printed MPDC certificate.
 */
#define MPDC_CERTIFICATE_LINE_LENGTH 64

/*!
 * \def MPDC_CERTIFICATE_MAXIMUM_PERIOD
 * \brief The maximum certificate validity period in milliseconds.
 */
#define MPDC_CERTIFICATE_MAXIMUM_PERIOD (MPDC_CERTIFICATE_DEFAULT_PERIOD * 2)

/*!
 * \def MPDC_CERTIFICATE_MINIMUM_PERIOD
 * \brief The minimum certificate validity period in milliseconds.
 */
#define MPDC_CERTIFICATE_MINIMUM_PERIOD ((uint64_t)1 * 24 * 60 * 60)

/*!
 * \def MPDC_CERTIFICATE_SERIAL_SIZE
 * \brief The certificate serial number field length.
 */
#define MPDC_CERTIFICATE_SERIAL_SIZE 16

/*!
 * \def MPDC_CERTIFICATE_HINT_SIZE
 * \brief The topological hint.
 */
#define MPDC_CERTIFICATE_HINT_SIZE (MPDC_CERTIFICATE_HASH_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE)

/*!
 * \def MPDC_CERTIFICATE_SIGNED_HASH_SIZE
 * \brief The size of the signature and hash field in a certificate.
 */
#define MPDC_CERTIFICATE_SIGNED_HASH_SIZE (MPDC_ASYMMETRIC_SIGNATURE_SIZE + MPDC_CERTIFICATE_HASH_SIZE)

/*!
 * \def MPDC_CERTIFICATE_VERSION_SIZE
 * \brief The version id.
 */
#define MPDC_CERTIFICATE_VERSION_SIZE 1

/*!
 * \def MPDC_CERTIFICATE_CHILD_SIZE
 * \brief The length of a child certificate.
 */
#define MPDC_CERTIFICATE_CHILD_SIZE (MPDC_CERTIFICATE_SIGNED_HASH_SIZE + \
	MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	MPDC_CERTIFICATE_ISSUER_SIZE + \
	MPDC_CERTIFICATE_SERIAL_SIZE + \
	MPDC_CERTIFICATE_SERIAL_SIZE + \
	MPDC_CERTIFICATE_EXPIRATION_SIZE + \
	MPDC_CERTIFICATE_DESIGNATION_SIZE + \
	MPDC_CERTIFICATE_ALGORITHM_SIZE + \
	MPDC_CERTIFICATE_VERSION_SIZE)

/*!
 * \def MPDC_CERTIFICATE_IDG_SIZE
 * \brief The length of an IDG certificate.
 */
#define MPDC_CERTIFICATE_IDG_SIZE (MPDC_ASYMMETRIC_SIGNATURE_SIZE + \
	MPDC_CERTIFICATE_HASH_SIZE + \
	MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	MPDC_CERTIFICATE_ISSUER_SIZE + \
	MPDC_CERTIFICATE_ADDRESS_SIZE + \
	MPDC_CERTIFICATE_SERIAL_SIZE + \
	MPDC_CERTIFICATE_SERIAL_SIZE + \
	MPDC_CERTIFICATE_EXPIRATION_SIZE + \
	MPDC_CERTIFICATE_DESIGNATION_SIZE + \
	MPDC_CERTIFICATE_ALGORITHM_SIZE + \
	MPDC_CERTIFICATE_VERSION_SIZE)

/*!
 * \def MPDC_CERTIFICATE_ROOT_SIZE
 * \brief The length of the root certificate.
 */
#define MPDC_CERTIFICATE_ROOT_SIZE (MPDC_CERTIFICATE_HASH_SIZE + \
	MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	MPDC_CERTIFICATE_ISSUER_SIZE + \
	MPDC_CERTIFICATE_SERIAL_SIZE + \
	MPDC_CERTIFICATE_EXPIRATION_SIZE + \
	MPDC_CERTIFICATE_ALGORITHM_SIZE + \
	MPDC_CERTIFICATE_VERSION_SIZE)

/*!
 * \def MPDC_CRYPTO_SYMMETRIC_KEY_SIZE
 * \brief The byte length of the symmetric cipher key.
 */
#define MPDC_CRYPTO_SYMMETRIC_KEY_SIZE 32

/*!
 * \def MPDC_CRYPTO_SYMMETRIC_NONCE_SIZE
 * \brief The byte length of the symmetric cipher nonce.
 */
#if defined(MPDC_USE_RCS_ENCRYPTION)
#	define MPDC_CRYPTO_SYMMETRIC_NONCE_SIZE 32
#else
#	define MPDC_CRYPTO_SYMMETRIC_NONCE_SIZE 16
#endif

/*!
 * \def MPDC_CRYPTO_SEED_SIZE
 * \brief The seed array byte size.
 */
#define MPDC_CRYPTO_SEED_SIZE 64

/*!
 * \def MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE
 * \brief The byte length of the symmetric token.
 */
#define MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE 32

/*!
 * \def MPDC_CRYPTO_SYMMETRIC_HASH_SIZE
 * \brief The hash function output byte size.
 */
#define MPDC_CRYPTO_SYMMETRIC_HASH_SIZE 32

/*!
 * \def MPDC_CRYPTO_SYMMETRIC_MAC_SIZE
 * \brief The MAC function output byte size.
 */
#if defined(MPDC_USE_RCS_ENCRYPTION)
#	if defined(MPDC_EXTENDED_SESSION_SECURITY)
#		define MPDC_CRYPTO_SYMMETRIC_MAC_SIZE 64
#	else
#		define MPDC_CRYPTO_SYMMETRIC_MAC_SIZE 32
#	endif
#else
#	define MPDC_CRYPTO_SYMMETRIC_MAC_SIZE 16
#endif

/*!
 * \def MPDC_CRYPTO_SYMMETRIC_SECRET_SIZE
 * \brief The shared secret byte size.
 */
#define MPDC_CRYPTO_SYMMETRIC_SECRET_SIZE 32

/*!
 * \def MPDC_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE
 * \brief The session key security size.
 */
#if defined(MPDC_EXTENDED_SESSION_SECURITY)
#	define MPDC_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE 64
#else
#	define MPDC_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE 32
#endif

/*!
 * \def MPDC_DLA_CONVERGENCE_INTERVAL
 * \brief The interval between agent convergence checks (default is 24 hours).
 */
#define MPDC_DLA_CONVERGENCE_INTERVAL (60 * 60 * 24)

/*!
 * \def MPDC_DLA_IP_MAX
 * \brief The maximum ip address length.
 */
#define MPDC_DLA_IP_MAX 0x41

/*!
 * \def MPDC_DLA_PENALTY_MAX
 * \brief The maximum unreachable penalty before the DLA is deemed unreliable.
 */
#define MPDC_DLA_PENALTY_MAX 0x100

/*!
 * \def MPDC_DLA_REDUCTION_INTERVAL
 * \brief The time before a penalty is reduced for a flapping DLA in milliseconds.
 */
#define MPDC_DLA_REDUCTION_INTERVAL 1000000

/*!
 * \def MPDC_DLA_UPDATE_WAIT_TIME
 * \brief The interval in milliseconds between topology full updates.
 *
 * Note: Default is 7 days.
 */
#define MPDC_DLA_UPDATE_WAIT_TIME (7 * 24 * 60 * 60)

/*!
 * \def MPDC_ERROR_STRING_DEPTH
 * \brief The number of error strings.
 */
#define MPDC_ERROR_STRING_DEPTH 26

/*!
 * \def MPDC_ERROR_STRING_WIDTH
 * \brief The maximum size in characters of an error string.
 */
#define MPDC_ERROR_STRING_WIDTH 128

/*!
 * \def MPDC_MESSAGE_MAX_SIZE
 * \brief The maximum message size (max signature + max certificate sizes).
 */
#define MPDC_MESSAGE_MAX_SIZE 1400000

/*!
 * \def MPDC_MFK_EXPIRATION_PERIOD
 * \brief The MFK validity period in milliseconds.
 */
#define MPDC_MFK_EXPIRATION_PERIOD ((uint64_t)60 * 24 * 60 * 60)

/*!
 * \def MPDC_MINIMUM_PATH_LENGTH
 * \brief The minimum file path length.
 */
#define MPDC_MINIMUM_PATH_LENGTH 9

/*!
 * \def MPDC_NETWORK_CONNECTION_MTU
 * \brief The MPDC packet buffer size.
 */
#define MPDC_NETWORK_CONNECTION_MTU 1500

/*!
 * \def MPDC_NETWORK_DOMAIN_NAME_MAX_SIZE
 * \brief The maximum domain name length in characters.
 * The last character must be a string terminator.
 */
#define MPDC_NETWORK_DOMAIN_NAME_MAX_SIZE 256

/*!
 * \def MPDC_NETWORK_MAX_AGENTS
 * \brief The maximum number of agent connections in a network.
 */
#define MPDC_NETWORK_MAX_AGENTS 1000000

/*!
 * \def MPDC_NETWORK_NODE_ID_SIZE
 * \brief The node identification string length.
 */
#define MPDC_NETWORK_NODE_ID_SIZE 16

/*!
 * \def MPDC_PERIOD_DAY_TO_SECONDS
 * \brief A period of one day in seconds.
 */
#define MPDC_PERIOD_DAY_TO_SECONDS (24 * 60 * 60)

/*!
 * \def MPDC_SOCKET_TERMINATOR_SIZE
 * \brief The packet delimiter byte size.
 */
#define MPDC_SOCKET_TERMINATOR_SIZE 1

/*!
 * \def MPDC_PACKET_ERROR_SIZE
 * \brief The packet error message byte size.
 */
#define MPDC_PACKET_ERROR_SIZE 1

/*!
 * \def MPDC_PACKET_HEADER_SIZE
 * \brief The MPDC packet header size.
 */
#define MPDC_PACKET_HEADER_SIZE 22

/*!
 * \def MPDC_PACKET_SUBHEADER_SIZE
 * \brief The MPDC packet sub-header size.
 */
#define MPDC_PACKET_SUBHEADER_SIZE 16

/*!
 * \def MPDC_PACKET_SEQUENCE_TERMINATOR
 * \brief The sequence number of a packet that closes a connection.
 */
#define MPDC_PACKET_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
 * \def MPDC_PACKET_TIME_SIZE
 * \brief The byte size of the serialized packet time parameter.
 */
#define MPDC_PACKET_TIME_SIZE 8

/*!
 * \def MPDC_PACKET_TIME_THRESHOLD
 * \brief The maximum number of seconds a packet is valid.
 */
#define MPDC_PACKET_TIME_THRESHOLD 60

/*!
 * \def MPDC_NETWORK_TERMINATION_MESSAGE_SIZE
 * \brief The network termination message size.
 */
#define MPDC_NETWORK_TERMINATION_MESSAGE_SIZE 1

/*!
 * \def MPDC_NETWORK_TERMINATION_PACKET_SIZE
 * \brief The network termination packet size.
 */
#define MPDC_NETWORK_TERMINATION_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + MPDC_NETWORK_TERMINATION_MESSAGE_SIZE)

/* enumerations */

/*!
 * \enum mpdc_configuration_sets
 * \brief The MPDC algorithm configuration sets.
 */
MPDC_EXPORT_API typedef enum mpdc_configuration_sets
{
	mpdc_configuration_set_none = 0x00,											/*!< No algorithm identifier is set */
	mpdc_configuration_set_dilithium1_kyber1_rcs256_shake256 = 0x01,			/*!< The Dilithium-S1/Kyber-S1/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_dilithium3_kyber3_rcs256_shake256 = 0x02,			/*!< The Dilithium-S3/Kyber-S3/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_dilithium5_kyber5_rcs256_shake256 = 0x03,			/*!< The Dilithium-S5/Kyber-S5/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_dilithium5_kyber6_rcs512_shake256 = 0x04,			/*!< The Dilithium-S5/Kyber-S6/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256 = 0x05,		/*!< The SPHINCS+-S1F/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256 = 0x06,		/*!< The SPHINCS+-S1S/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256 = 0x07,		/*!< The SPHINCS+-S3F/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256 = 0x08,		/*!< The SPHINCS+-S3S/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256 = 0x09,		/*!< The SPHINCS+-S5F/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256 = 0x0A,		/*!< The SPHINCS+-S5S/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256 = 0x0B,		/*!< The SPHINCS+-S5F/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256 = 0x0C,		/*!< The SPHINCS+-S5S/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256 = 0x0D,		/*!< The SPHINCS+-S5F/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
	mpdc_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256 = 0x0E,		/*!< The SPHINCS+-S5S/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
} mpdc_configuration_sets;

/*!
 * \enum mpdc_network_designations
 * \brief The MPDC device designation.
 */
MPDC_EXPORT_API typedef enum mpdc_network_designations
{
	mpdc_network_designation_none = 0x00,							/*!< No designation was selected */
	mpdc_network_designation_agent = 0x01,							/*!< The device is an agent */
	mpdc_network_designation_client = 0x02,							/*!< The device is a client */
	mpdc_network_designation_dla = 0x03,							/*!< The device is the DLA */
	mpdc_network_designation_idg = 0x04,							/*!< The device is an inter-domain gateway */
	mpdc_network_designation_mas = 0x05,							/*!< The device is a server */
	mpdc_network_designation_remote = 0x06,							/*!< The device is a remote agent */
	mpdc_network_designation_rds = 0x07,							/*!< The device is an RDS security server */
	mpdc_network_designation_revoked = 0x08,						/*!< The device has been revoked */
	mpdc_network_designation_all = 0xFF,							/*!< Every server and client device on the network */
} mpdc_network_designations;

/*!
 * \enum mpdc_network_errors
 * \brief The MPDC network error values.
 */
MPDC_EXPORT_API typedef enum mpdc_network_errors
{
	mpdc_network_error_none = 0x00,									/*!< No error was detected */
	mpdc_network_error_accept_fail = 0x01,							/*!< The socket accept function returned an error */
	mpdc_network_error_auth_failure = 0x02,							/*!< The cipher authentication has failed */
	mpdc_network_error_bad_keep_alive = 0x03,						/*!< The keep alive check failed */
	mpdc_network_error_channel_down = 0x04,							/*!< The communications channel has failed */
	mpdc_network_error_connection_failure = 0x05,					/*!< The device could not make a connection to the remote host */
	mpdc_network_error_decryption_failure = 0x06,					/*!< The decryption authentication has failed */
	mpdc_network_error_establish_failure = 0x07,					/*!< The transmission failed at the kex establish phase */
	mpdc_network_error_general_failure = 0x08,						/*!< The connection experienced an unexpected error */
	mpdc_network_error_hosts_exceeded = 0x09,						/*!< The server has run out of socket connections */
	mpdc_network_error_identity_unknown = 0x10,						/*!< The random generator experienced a failure */
	mpdc_network_error_invalid_input = 0x1A,						/*!< The input is invalid */
	mpdc_network_error_invalid_request = 0x1B,						/*!< The request is invalid */
	mpdc_network_error_keep_alive_expired = 0x1C,					/*!< The keep alive has expired with no response */
	mpdc_network_error_keep_alive_timeout = 0x1D,					/*!< The keepalive failure counter has exceeded maximum  */
	mpdc_network_error_kex_auth_failure = 0x1E,						/*!< The kex authentication has failed */
	mpdc_network_error_key_not_recognized = 0x1F,					/*!< The key-id is not recognized */
	mpdc_network_error_key_has_expired = 0x20,						/*!< The certificate has expired */
	mpdc_network_error_listener_fail = 0x21,						/*!< The listener function failed to initialize */
	mpdc_network_error_memory_allocation = 0x22,					/*!< The server has run out of memory */
	mpdc_network_error_packet_unsequenced = 0x23,					/*!< The random generator experienced a failure */
	mpdc_network_error_random_failure = 0x24,						/*!< The random generator experienced a failure */
	mpdc_network_error_ratchet_fail = 0x25,							/*!< The ratchet operation has failed */
	mpdc_network_error_receive_failure = 0x26,						/*!< The receiver failed at the network layer */
	mpdc_network_error_transmit_failure = 0x27,						/*!< The transmitter failed at the network layer */
	mpdc_network_error_unknown_protocol = 0x28,						/*!< The protocol version is unknown */
	mpdc_network_error_unsequenced = 0x29,							/*!< The packet was received out of sequence */
	mpdc_network_error_verify_failure = 0x2A,						/*!< The expected data could not be verified */
} mpdc_network_errors;

/*!
 * \enum mpdc_network_flags
 * \brief The MPDC network flags.
 */
MPDC_EXPORT_API typedef enum mpdc_network_flags
{
	mpdc_network_flag_none = 0x00,									/*!< No flag was selected */
	mpdc_network_flag_connection_terminate_request = 0x01,			/*!< The packet contains a connection termination message  */
	mpdc_network_flag_error_condition = 0x02,						/*!< The connection experienced an error message*/
	mpdc_network_flag_fragment_collection_request = 0x03,			/*!< The packet contains a server fragment collection request message */
	mpdc_network_flag_fragment_collection_response = 0x04,			/*!< The packet contains an agent fragment collection response message */
	mpdc_network_flag_fragment_request = 0x05,						/*!< The packet contains a server fragment key request message */
	mpdc_network_flag_fragment_response = 0x06,						/*!< The packet contains an agent fragment key response message */
	mpdc_network_flag_fragment_query_request = 0x07,				/*!< The packet contains a server fragment key request message */
	mpdc_network_flag_fragment_query_response = 0x08,				/*!< The packet contains an agent fragment key response message */
	mpdc_network_flag_incremental_update_request = 0x09,			/*!< The packet contains an incremental update request message */
	mpdc_network_flag_incremental_update_response = 0x0A,			/*!< The packet contains an incremental update response message */
	mpdc_network_flag_register_request = 0x0B,						/*!< The packet contains a join request message */
	mpdc_network_flag_register_response = 0x0C,						/*!< The packet contains a join response message */
	mpdc_network_flag_register_update_request = 0x0D,				/*!< The packet contains a join update request message */
	mpdc_network_flag_register_update_response = 0x0E,				/*!< The packet contains a join update response message */
	mpdc_network_flag_keep_alive_request = 0x0F,					/*!< The packet contains a keep alive request */
	mpdc_network_flag_keep_alive_response = 0x10,					/*!< The packet contains a keep alive response */
	mpdc_network_flag_mfk_establish = 0x11,							/*!< The packet contains a server master fragment key establish message */
	mpdc_network_flag_mfk_request = 0x12,							/*!< The packet contains a server master fragment key request message */
	mpdc_network_flag_mfk_response = 0x13,							/*!< The packet contains a client mfk exchange response message */
	mpdc_network_flag_mfk_verify = 0x14,							/*!< The packet contains a server master fragment key verify message */
	mpdc_network_flag_network_announce_broadcast = 0x15,			/*!< The packet contains a topology announce broadcast */
	mpdc_network_flag_network_converge_request = 0x16,				/*!< The packet contains a network converge request message */
	mpdc_network_flag_network_converge_response = 0x17,				/*!< The packet contains a network converge response message */
	mpdc_network_flag_network_converge_update = 0x18,				/*!< The packet contains a network converge update message */
	mpdc_network_flag_network_resign_request = 0x19,				/*!< The packet contains a network resignation request message */
	mpdc_network_flag_network_resign_response = 0x1A,				/*!< The packet contains a network resignation response message */
	mpdc_network_flag_network_revocation_broadcast = 0x1B,			/*!< The packet contains a certificate revocation broadcast */
	mpdc_network_flag_network_signature_request = 0x1C,				/*!< The packet contains a certificate signing request */
	mpdc_network_flag_system_error_condition = 0x1D,				/*!< The packet contains an error condition message */
	mpdc_network_flag_tunnel_connection_terminate = 0x1E,			/*!< The packet contains a socket close message */
	mpdc_network_flag_tunnel_encrypted_message = 0x1F,				/*!< The packet contains an encrypted message */
	mpdc_network_flag_tunnel_session_established = 0x20,			/*!< The exchange is in the established state */
	mpdc_network_flag_tunnel_transfer_request = 0x21,				/*!< Reserved - The host has received a transfer request */
	mpdc_network_flag_topology_query_request = 0x22,				/*!< The packet contains a topology query request message */
	mpdc_network_flag_topology_query_response = 0x23,				/*!< The packet contains a topology query response message */
	mpdc_network_flag_topology_status_request = 0x24,				/*!< The packet contains a topology status request message */
	mpdc_network_flag_topology_status_response = 0x25,				/*!< The packet contains a topology status response message */
	mpdc_network_flag_topology_status_available = 0x26,				/*!< The packet contains a topology status available message */
	mpdc_network_flag_topology_status_synchronized = 0x27,			/*!< The packet contains a topology status synchronized message */
	mpdc_network_flag_topology_status_unavailable = 0x28,			/*!< The packet contains a topology status unavailable message */
	mpdc_network_flag_network_remote_signing_request = 0x29,		/*!< The packet contains a remote signing request message */
	mpdc_network_flag_network_remote_signing_response = 0x2A,		/*!< The packet contains a remote signing response message */
} mpdc_network_flags;

/*!
 * \enum mpdc_protocol_errors
 * \brief The MPDC protocol error values.
 */
MPDC_EXPORT_API typedef enum mpdc_protocol_errors
{
	mpdc_protocol_error_none = 0x00,								/*!< No error was detected */
	mpdc_protocol_error_authentication_failure = 0x01,				/*!< The symmetric cipher had an authentication failure */
	mpdc_protocol_error_certificate_not_found = 0x02,				/*!< The node certificate could not be found */
	mpdc_protocol_error_channel_down = 0x03,						/*!< The communications channel has failed */
	mpdc_protocol_error_connection_failure = 0x04,					/*!< The device could not make a connection to the remote host */
	mpdc_protocol_error_connect_failure = 0x05,						/*!< The transmission failed at the KEX connection phase */
	mpdc_protocol_error_convergence_failure = 0x06,					/*!< The convergence call has returned an error */
	mpdc_protocol_error_convergence_synchronized = 0x07,			/*!< The database is already synchronized */
	mpdc_protocol_error_decapsulation_failure = 0x08,				/*!< The asymmetric cipher failed to decapsulate the shared secret */
	mpdc_protocol_error_decoding_failure = 0x09,					/*!< The node or certificate decoding failed */
	mpdc_protocol_error_decryption_failure = 0x0A,					/*!< The decryption authentication has failed */
	mpdc_protocol_error_establish_failure = 0x0B,					/*!< The transmission failed at the KEX establish phase */
	mpdc_protocol_error_exchange_failure = 0x0C,					/*!< The transmission failed at the KEX exchange phase */
	mpdc_protocol_error_file_not_deleted = 0x0D,					/*!< The application could not delete a local file */
	mpdc_protocol_error_file_not_found = 0x0E,						/*!< The file could not be found */
	mpdc_protocol_error_file_not_written = 0x0F,					/*!< The file could not be written to storage */
	mpdc_protocol_error_hash_invalid = 0x10,						/*!< The public-key hash is invalid */
	mpdc_protocol_error_hosts_exceeded = 0x11,						/*!< The server has run out of socket connections */
	mpdc_protocol_error_invalid_request = 0x12,						/*!< The packet flag was unexpected */
	mpdc_protocol_error_certificate_expired = 0x13,					/*!< The certificate has expired */
	mpdc_protocol_error_key_expired = 0x14,							/*!< The MPDC public key has expired  */
	mpdc_protocol_error_key_unrecognized = 0x15,					/*!< The key identity is unrecognized */
	mpdc_protocol_error_listener_fail = 0x16,						/*!< The listener function failed to initialize */
	mpdc_protocol_error_memory_allocation = 0x17,					/*!< The server has run out of memory */
	mpdc_protocol_error_message_time_invalid = 0x18,				/*!< The network time is invalid or has substantial delay */
	mpdc_protocol_error_message_verification_failure = 0x19,		/*!< The expected data could not be verified */
	mpdc_protocol_error_no_usable_address = 0x1A,					/*!< The server has no usable IP address, assign in configuration */
	mpdc_protocol_error_node_not_available = 0x1B,					/*!< The node is not available for a session */
	mpdc_protocol_error_node_not_found = 0x1C,						/*!< The node could not be found in the database */
	mpdc_protocol_error_node_was_registered = 0x1D,					/*!< The node was previously registered in the database */
	mpdc_protocol_error_operation_cancelled = 0x1E,					/*!< The operation was cancelled by the user */
	mpdc_protocol_error_packet_header_invalid = 0x1F,				/*!< The packet header received was invalid */
	mpdc_protocol_error_packet_unsequenced = 0x20,					/*!< The packet was received out of sequence */
	mpdc_protocol_error_receive_failure = 0x21,						/*!< The receiver failed at the network layer */
	mpdc_protocol_error_root_signature_invalid = 0x22,				/*!< The root signature failed authentication */
	mpdc_protocol_error_serialization_failure = 0x23,				/*!< The certificate could not be serialized */
	mpdc_protocol_error_signature_failure = 0x24,					/*!< The signature scheme could not sign a message */
	mpdc_protocol_error_signing_failure = 0x25,						/*!< The transmission failed to sign the data */
	mpdc_protocol_error_socket_binding = 0x26,						/*!< The socket could not be bound to an IP address */
	mpdc_protocol_error_socket_creation = 0x27,						/*!< The socket could not be created */
	mpdc_protocol_error_transmit_failure = 0x28,					/*!< The transmitter failed at the network layer */
	mpdc_protocol_error_topology_no_agent = 0x29,					/*!< The topological database has no agent entries */
	mpdc_protocol_error_unknown_protocol = 0x2A,					/*!< The protocol string was not recognized */
	mpdc_protocol_error_verification_failure = 0x2B,				/*!< The transmission failed at the KEX verify phase */
} mpdc_protocol_errors;

/*!
 * \enum mpdc_version_sets
 * \brief The MPDC version sets.
 */
MPDC_EXPORT_API typedef enum mpdc_version_sets
{
	mpdc_version_set_none = 0x00,									/*!< No version identifier is set */
	mpdc_version_set_one_zero = 0x01,								/*!< The 1.0 version identifier */
} mpdc_version_sets;

/* public structures */

/*!
 * \struct mpdc_certificate_expiration
 * \brief The certificate expiration time structure.
 */
MPDC_EXPORT_API typedef struct mpdc_certificate_expiration
{
	uint64_t from;													/*!< The starting time in seconds */
	uint64_t to;													/*!< The expiration time in seconds */
} mpdc_certificate_expiration;

/*!
 * \struct mpdc_child_certificate
 * \brief The child certificate structure.
 */
MPDC_EXPORT_API typedef struct mpdc_child_certificate
{
	uint8_t csig[MPDC_CERTIFICATE_SIGNED_HASH_SIZE];				/*!< The certificate's signed hash */
	uint8_t verkey[MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public verification key */
	char issuer[MPDC_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer */
	uint8_t serial[MPDC_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	uint8_t rootser[MPDC_CERTIFICATE_SERIAL_SIZE];					/*!< The root certificate's serial number */
	mpdc_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	mpdc_network_designations designation;							/*!< The certificate type designation */
	mpdc_configuration_sets algorithm;								/*!< The algorithm configuration identifier */
	uint8_t version;												/*!< The certificate version */
} mpdc_child_certificate;

/*!
 * \def MPDC_X509_CERTIFICATE_SIZE
 * \brief x509 implementation where algorithm/signature output size is stored.
 */
#define MPDC_X509_CERTIFICATE_SIZE 4096

/*!
 * \def MPDC_IDG_HINT_SIZE
 * \brief Hint query; certificate hash, root serial number hi=(H(cert) | rsn)
 * idg query asks if a peer knows of the root security server for a domain;
 * if the peer does know the root of the other domain, it sends back information
 * about that rds (address, certificate hash, root serial number, and trust metric).
 */
#define MPDC_IDG_HINT_SIZE (MPDC_CERTIFICATE_HASH_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE)

/*!
 * \struct mpdc_idg_hint
 * \brief The IDG hint structure.
 */
MPDC_EXPORT_API typedef struct mpdc_idg_hint
{
	uint8_t chash[MPDC_CERTIFICATE_HASH_SIZE];						/*!< The remote certificate's signed hash */
	uint8_t rootser[MPDC_CERTIFICATE_SERIAL_SIZE];					/*!< The remote certificate's root serial number */
} mpdc_idg_hint;

/*!
 * \struct mpdc_idg_certificate
 * \brief The IDG certificate structure.
 *
 * The IDG certificate structure contains the necessary fields for identification and verification
 * of an inter-domain gateway. (Note: A field for a serialized x509 certificate may be added in future revisions.)
 */
MPDC_EXPORT_API typedef struct mpdc_idg_certificate
{
	uint8_t csig[MPDC_CERTIFICATE_SIGNED_HASH_SIZE];				/*!< The certificate's signed hash */
	uint8_t vkey[MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public verification key */
	uint8_t xcert[MPDC_X509_CERTIFICATE_SIZE];						/*!< The serialized X509 certificate */
	uint8_t serial[MPDC_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	uint8_t rootser[MPDC_CERTIFICATE_SERIAL_SIZE];					/*!< The root certificate's serial number */
	uint8_t hint[MPDC_CERTIFICATE_HINT_SIZE];						/*!< The certificate's topological hint  */
	char issuer[MPDC_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer */
	mpdc_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	mpdc_network_designations designation;							/*!< The certificate type designation */
	mpdc_configuration_sets algorithm;								/*!< The algorithm configuration identifier */
	uint8_t version;												/*!< The certificate version */
} mpdc_idg_certificate;

/*!
 * \struct mpdc_connection_state
 * \brief The MPDC socket connection state structure.
 */
MPDC_EXPORT_API typedef struct mpdc_connection_state
{
	qsc_socket target;												/*!< The target socket structure */
	mpdc_cipher_state rxcpr;											/*!< The receive channel cipher state */
	mpdc_cipher_state txcpr;											/*!< The transmit channel cipher state */
	uint64_t rxseq;													/*!< The receive channel's packet sequence number */
	uint64_t txseq;													/*!< The transmit channel's packet sequence number */
	uint32_t instance;												/*!< The connection's instance count */
	mpdc_network_flags exflag;										/*!< The network stage flag */
} mpdc_connection_state;

/*!
 * \struct mpdc_keep_alive_state
 * \brief The MPDC keep alive state structure.
 */
MPDC_EXPORT_API typedef struct mpdc_keep_alive_state
{
	qsc_socket target;												/*!< The target socket structure */
	uint64_t etime;													/*!< The keep alive epoch time  */
	uint64_t seqctr;												/*!< The keep alive packet sequence counter  */
	bool recd;														/*!< The keep alive response received status  */
} mpdc_keep_alive_state;

/*!
 * \struct mpdc_mfkey_state
 * \brief The MPDC master fragment key structure.
 */
typedef struct mpdc_mfkey_state
{
	uint8_t serial[MPDC_CERTIFICATE_SERIAL_SIZE];					/*!< The mfk serial number  */
	uint8_t mfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE];					/*!< The master fragment key */
} mpdc_mfkey_state;

/*!
 * \struct mpdc_network_packet
 * \brief The MPDC packet structure.
 */
MPDC_EXPORT_API typedef struct mpdc_network_packet
{
	uint8_t flag;													/*!< The packet flag */
	uint32_t msglen;												/*!< The packet's message length */
	uint64_t sequence;												/*!< The packet sequence number */
	uint64_t utctime;												/*!< The UTC time the packet was created (in seconds) */
	uint8_t* pmessage;												/*!< A pointer to the packet's message buffer */
} mpdc_network_packet;

/*!
 * \struct mpdc_root_certificate
 * \brief The root certificate structure.
 *
 * The root certificate structure contains the fields for the MPDC root (trust anchor)
 * including the public verification key, issuer information, certificate serial, validity times,
 * algorithm identifier, and version.
 */
MPDC_EXPORT_API typedef struct mpdc_root_certificate
{
	uint8_t verkey[MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public key */
	char issuer[MPDC_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer text name */
	uint8_t serial[MPDC_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	mpdc_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	mpdc_configuration_sets algorithm;								/*!< The signature algorithm identifier */
	mpdc_version_sets version;										/*!< The certificate version type */
} mpdc_root_certificate;

/*!
 * \struct mpdc_serialized_symmetric_key
 * \brief The structure for a serialized symmetric key.
 */
MPDC_EXPORT_API typedef struct mpdc_serialized_symmetric_key
{
	uint64_t keyid;													/*!< The key identity */
	uint8_t key[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE];					/*!< The symmetric key */
	uint8_t nonce[MPDC_CRYPTO_SYMMETRIC_NONCE_SIZE];				/*!< The symmetric nonce */
} mpdc_serialized_symmetric_key;

/*!
 * \struct mpdc_signature_keypair
 * \brief The MPDC asymmetric signature scheme key container.
 */
MPDC_EXPORT_API typedef struct mpdc_signature_keypair
{
	uint8_t prikey[MPDC_ASYMMETRIC_SIGNING_KEY_SIZE];				/*!< The secret signing key */
	uint8_t pubkey[MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The public signature verification key */
} mpdc_signature_keypair;

/*!
 * \struct mpdc_cipher_keypair
 * \brief The MPDC asymmetric cipher key container.
 */
MPDC_EXPORT_API typedef struct mpdc_cipher_keypair
{
	uint8_t prikey[MPDC_ASYMMETRIC_PRIVATE_KEY_SIZE];				/*!< The asymmetric cipher private key */
	uint8_t pubkey[MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE];				/*!< The asymmetric cipher public key */
} mpdc_cipher_keypair;

/* public key encoding constants */

/** \cond */

#define MPDC_CERTIFICATE_SEPERATOR_SIZE 1
#define MPDC_CHILD_CERTIFICATE_HEADER_SIZE 64
#define MPDC_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE 30
#define MPDC_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE 23
#define MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE 9
#define MPDC_CHILD_CERTIFICATE_NAME_PREFIX_SIZE 7
#define MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE 9
#define MPDC_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE 14
#define MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13
#define MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6
#define MPDC_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12
#define MPDC_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE 10
#define MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE 14
#define MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE 10
#define MPDC_CHILD_CERTIFICATE_FOOTER_SIZE 64
#define MPDC_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE 19

static const char MPDC_CHILD_CERTIFICATE_HEADER[MPDC_CHILD_CERTIFICATE_HEADER_SIZE] = "-----------BEGIN MPDC CHILD PUBLIC CERTIFICATE BLOCK-----------";
static const char MPDC_CHILD_CERTIFICATE_ROOT_HASH_PREFIX[MPDC_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE] = "Root Signed Public Key Hash: ";
static const char MPDC_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX[MPDC_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE] = "Public Signature Key: ";
static const char MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX[MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char MPDC_CHILD_CERTIFICATE_NAME_PREFIX[MPDC_CHILD_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
static const char MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX[MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char MPDC_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX[MPDC_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE] = "Root Serial: ";
static const char MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX[MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX[MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = " To: ";
static const char MPDC_CHILD_CERTIFICATE_ALGORITHM_PREFIX[MPDC_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char MPDC_CHILD_CERTIFICATE_VERSION_PREFIX[MPDC_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX[MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE] = "Designation: ";
static const char MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX[MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE] = "Address: ";
static const char MPDC_CHILD_CERTIFICATE_FOOTER[MPDC_CHILD_CERTIFICATE_FOOTER_SIZE] = "------------END MPDC CHILD PUBLIC CERTIFICATE BLOCK------------";
static const char MPDC_CHILD_CERTIFICATE_DEFAULT_NAME[MPDC_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE] = " Child Certificate";

#define MPDC_NETWORK_DESIGNATION_SIZE 33
static const char MPDC_NETWORK_DESIGNATION_NONE[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_none";
static const char MPDC_NETWORK_DESIGNATION_AGENT[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_agent";
static const char MPDC_NETWORK_DESIGNATION_CLIENT[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_client";
static const char MPDC_NETWORK_DESIGNATION_DLA[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_dla";
static const char MPDC_NETWORK_DESIGNATION_IDG[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_idg";
static const char MPDC_NETWORK_DESIGNATION_REMOTE[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_remote";
static const char MPDC_NETWORK_DESIGNATION_ROOT[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_rds";
static const char MPDC_NETWORK_DESIGNATION_SERVER[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_mas";
static const char MPDC_NETWORK_DESIGNATION_ALL[MPDC_NETWORK_DESIGNATION_SIZE] = "mpdc_network_designation_all";

/** \endcond */

/*!
 * \def MPDC_PROTOCOL_SET_SIZE
 * \brief The size of the protocol configuration string.
 */
#define MPDC_PROTOCOL_SET_SIZE 41

/* Valid parameter sets: 
Kyber-S1, Dilithium-S1
Kyber-S3, Dilithium-S3
Kyber-S5, Dilithium-S5
Kyber-S6, Dilithium-S5
McEliece-S1, Sphincs-S1(f,s)
McEliece-S3, Sphincs-S3(f,s)
McEliece-S5, Sphincs-S5(f,s)
McEliece-S6, Sphincs-S5(f,s)
McEliece-S7, Sphincs-S6(f,s) */

/** \cond */

#if defined(MPDC_PARAMATERS_DILITHIUM_KYBER_D1K1)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "dilithium-s1_kyber-s1_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_dilithium1_kyber1_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_DILITHIUM_KYBER_D3K3)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "dilithium-s3_kyber-s3_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_dilithium3_kyber3_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_DILITHIUM_KYBER_D5K5)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s5_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_dilithium5_kyber5_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_DILITHIUM_KYBER_D5K6)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s6_rcs-512_sha3-512";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_dilithium5_kyber6_rcs512_shake512;
#elif defined(MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF1M1) 
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-1f_mceliece-s1_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSPLUS_S1S128SHAKERS)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-1s_mceliece-s1_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF3M3)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-3f_mceliece-s3_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSPLUS_S3S192SHAKERS)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-3s_mceliece-s3_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF5M5)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s5_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s5_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF5M6)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s6_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s6_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSF_MCELIECE_SF5M7)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s7_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256;
#elif defined(MPDC_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char MPDC_CONFIG_STRING[MPDC_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s7_rcs-256_sha3-256";
static const mpdc_configuration_sets MPDC_CONFIGURATION_SET = mpdc_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256;
#else
#	error Invalid parameter set!
#endif

/** \endcond */

/** \cond */

#define MPDC_ROOT_CERTIFICATE_HEADER_SIZE 64
#define MPDC_ROOT_CERTIFICATE_HASH_PREFIX_SIZE 19
#define MPDC_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE 13
#define MPDC_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE 9
#define MPDC_ROOT_CERTIFICATE_NAME_PREFIX_SIZE 7
#define MPDC_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE 9
#define MPDC_ROOT_CERTIFICATE_FOOTER_SIZE 64
#define MPDC_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13
#define MPDC_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6
#define MPDC_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12
#define MPDC_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE 10
#define MPDC_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE 18
#define MPDC_ACTIVE_VERSION_STRING_SIZE 5

/** \endcond */

/** \cond */

static const char MPDC_ROOT_CERTIFICATE_HEADER[MPDC_ROOT_CERTIFICATE_HEADER_SIZE] = "------------BEGIN MPDC ROOT PUBLIC CERTIFICATE BLOCK-----------";
static const char MPDC_ROOT_CERTIFICATE_ISSUER_PREFIX[MPDC_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char MPDC_ROOT_CERTIFICATE_NAME_PREFIX[MPDC_ROOT_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
static const char MPDC_ROOT_CERTIFICATE_SERIAL_PREFIX[MPDC_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char MPDC_ROOT_CERTIFICATE_VALID_FROM_PREFIX[MPDC_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char MPDC_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX[MPDC_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = " To: ";
static const char MPDC_ROOT_CERTIFICATE_ALGORITHM_PREFIX[MPDC_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char MPDC_ROOT_CERTIFICATE_VERSION_PREFIX[MPDC_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char MPDC_ROOT_CERTIFICATE_HASH_PREFIX[MPDC_ROOT_CERTIFICATE_HASH_PREFIX_SIZE] = "Certificate Hash: ";
static const char MPDC_ROOT_CERTIFICATE_PUBLICKEY_PREFIX[MPDC_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE] = "Public Key: ";
static const char MPDC_ROOT_CERTIFICATE_FOOTER[MPDC_ROOT_CERTIFICATE_FOOTER_SIZE] = "------------END MPDC ROOT PUBLIC CERTIFICATE BLOCK-------------";
static const char MPDC_ROOT_CERTIFICATE_DEFAULT_NAME[MPDC_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE] = " Root Certificate";

static const char MPDC_ACTIVE_VERSION_STRING[MPDC_ACTIVE_VERSION_STRING_SIZE] = "0x01";
static const char MPDC_CERTIFICATE_CHILD_EXTENSION[] = ".ccert";
static const char MPDC_CERTIFICATE_MFCOL_EXTENSION[] = ".mfcol";
static const char MPDC_CERTIFICATE_ROOT_EXTENSION[] = ".rcert";
static const char MPDC_CERTIFICATE_TOPOLOGY_EXTENSION[] = ".dtop";
static const char MPDC_APPLICATION_ROOT_PATH[] = "\\MPDC";
static const char MPDC_CERTIFICATE_BACKUP_PATH[] = "\\Backup";
static const char MPDC_CERTIFICATE_STORE_PATH[] = "\\Certificates";
static const char MPDC_ROOT_CERTIFICATE_PATH[] = "\\Root";
static const char MPDC_CERTIFICATE_TOPOLOGY_PATH[] = "\\Topology";

/** \endcond */

#define MPDC_NETWORK_ERROR_STRING_DEPTH 28
#define MPDC_NETWORK_ERROR_STRING_SIZE 128

/** \cond */

static const char MPDC_NETWORK_ERROR_STRINGS[MPDC_NETWORK_ERROR_STRING_DEPTH][MPDC_NETWORK_ERROR_STRING_SIZE] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The cipher authentication has failed",
	"The keep alive check failed",
	"The communications channel has failed",
	"The device could not make a connnection to the remote host",
	"The decryption authentication has failed",
	"The transmission failed at the kex establish phase",
	"The connection experienced an unexpected error",
	"The server has run out of socket connections",
	"The random generator experienced a failure",
	"The input is invalid",
	"The request is invalid",
	"The keep alive has expired with no response",
	"The keepalive failure counter has exceeded maximum ",
	"The kex authentication has failed",
	"The key-id is not recognized",
	"The certificate has expired",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The random generator experienced a failure",
	"The random generator experienced a failure",
	"The ratchet operation has failed",
	"The receiver failed at the network layer",
	"The transmitter failed at the network layer",
	"The protocol version is unknown",
	"The packet was received out of sequence",
	"The expected data could not be verified"
};

#define MPDC_PROTOCOL_ERROR_STRING_DEPTH 44
#define MPDC_PROTOCOL_ERROR_STRING_SIZE 128

static const char MPDC_PROTOCOL_ERROR_STRINGS[MPDC_PROTOCOL_ERROR_STRING_DEPTH][MPDC_PROTOCOL_ERROR_STRING_SIZE] =
{
	"No error was detected",
	"The symmetric cipher had an authentication failure",
	"The node certificate could not be found",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The convergence call has returned an error",
	"The database is already synchronized",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The node or certificate decoding failed",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The application could not delete a local file",
	"The file could not be found",
	"The file could not be written to storage",
	"The public-key hash is invalid",
	"The server has run out of socket connections",
	"The packet flag was unexpected",
	"The certificate has expired and is invalid",
	"The MPDC public key has expired ",
	"The key identity is unrecognized",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The network time is invalid or has substantial delay",
	"The expected data could not be verified",
	"The server has no usable IP address, assign in configuration",
	"The node is offline or not available for connection",
	"The node could not be found in the database",
	"The node was previously registered in the database",
	"The operation was cancelled by the user",
	"The packet header received was invalid",
	"The packet was received out of sequence",
	"The receiver failed at the network layer",
	"The root signature failed authentication",
	"The certificate could not be serialized",
	"The signature scheme could not sign a message",
	"The transmission failed to sign the data",
	"The socket could not be bound to an IP address",
	"The socket could not be created",
	"The transmitter failed at the network layer",
	"The topological database has no agent entries",
	"The protocol string was not recognized",
	"The transmission failed at the KEX verify phase"
};

/** \endcond */

/* API */

/**
 * \brief Close the network connection between hosts.
 *
 * \param rsock A pointer to the socket structure representing the connection.
 * \param err The network error code to report.
 * \param notify If true, notify the remote host that the connection is closing.
 */
MPDC_EXPORT_API void mpdc_connection_close(qsc_socket* rsock, mpdc_network_errors err, bool notify);

/**
 * \brief Decrypt a message and copy it to the output buffer.
 *
 * \param cns A pointer to the connection state structure.
 * \param message The output array for the decrypted message.
 * \param msglen A pointer to a variable that will receive the length of the decrypted message.
 * \param packetin [const] A pointer to the input packet structure.
 *
 * \return Returns the network error state.
 */
MPDC_EXPORT_API mpdc_network_errors mpdc_decrypt_packet(mpdc_connection_state* cns, uint8_t* message, size_t* msglen, const mpdc_network_packet* packetin);

/**
 * \brief Encrypt a message and build an output packet.
 *
 * \param cns A pointer to the connection state structure.
 * \param packetout A pointer to the output packet structure.
 * \param message [const] The input message array.
 * \param msglen The length of the input message.
 *
 * \return Returns the network error state.
 */
MPDC_EXPORT_API mpdc_network_errors mpdc_encrypt_packet(mpdc_connection_state* cns, mpdc_network_packet* packetout, const uint8_t* message, size_t msglen);

/**
 * \brief Dispose of the tunnel connection state.
 *
 * \param cns A pointer to the connection state structure to dispose.
 */
MPDC_EXPORT_API void mpdc_connection_state_dispose(mpdc_connection_state* cns);

/**
 * \brief Return a pointer to a string description of a network error code.
 *
 * \param error The network error code.
 *
 * \return Returns a pointer to an error string or NULL if the code is unrecognized.
 */
MPDC_EXPORT_API const char* mpdc_network_error_to_string(mpdc_network_errors error);

/**
 * \brief Return a pointer to a string description of a protocol error code.
 *
 * \param error The protocol error code.
 *
 * \return Returns a pointer to an error string or NULL if the code is unrecognized.
 */
MPDC_EXPORT_API const char* mpdc_protocol_error_to_string(mpdc_protocol_errors error);

/**
 * \brief Clear the state of a network packet.
 *
 * \param packet A pointer to the packet structure to clear.
 */
MPDC_EXPORT_API void mpdc_packet_clear(mpdc_network_packet* packet);

/**
 * \brief Populate a packet structure with an error message.
 *
 * \param packet A pointer to the packet structure.
 * \param error The protocol error code to embed in the packet.
 */
MPDC_EXPORT_API void mpdc_packet_error_message(mpdc_network_packet* packet, mpdc_protocol_errors error);

/**
 * \brief Deserialize a byte array into a packet header.
 *
 * \param header [const] The header byte array to deserialize.
 * \param packet A pointer to the packet structure that will be populated.
 */
MPDC_EXPORT_API void mpdc_packet_header_deserialize(const uint8_t* header, mpdc_network_packet* packet);

/**
 * \brief Serialize a packet header into a byte array.
 *
 * \param packet [const] A pointer to the packet structure to serialize.
 * \param header The byte array that will receive the serialized header.
 */
MPDC_EXPORT_API void mpdc_packet_header_serialize(const mpdc_network_packet* packet, uint8_t* header);

/**
 * \brief Set the local UTC time in the packet header.
 *
 * \param packet A pointer to the network packet.
 */
MPDC_EXPORT_API void mpdc_packet_set_utc_time(mpdc_network_packet* packet);

/**
 * \brief Check if the packet's UTC time is within the valid time threshold.
 *
 * \param packet [const] A pointer to the network packet.
 *
 * \return Returns true if the packet was received within the valid time threshold.
 */
MPDC_EXPORT_API bool mpdc_packet_time_valid(const mpdc_network_packet* packet);

/**
 * \brief Serialize a network packet to a byte stream.
 *
 * \param packet [const] A pointer to the packet.
 * \param pstream A pointer to the output byte stream.
 *
 * \return Returns the size of the serialized byte stream.
 */
MPDC_EXPORT_API size_t mpdc_packet_to_stream(const mpdc_network_packet* packet, uint8_t* pstream);

/**
 * \brief Deserialize a byte stream into a network packet.
 *
 * \param pstream [const] The byte stream containing the packet data.
 * \param packet A pointer to the packet structure to populate.
 */
MPDC_EXPORT_API void mpdc_stream_to_packet(const uint8_t* pstream, mpdc_network_packet* packet);

#endif