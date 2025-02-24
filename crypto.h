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

#ifndef MPDC_CRYPTO_H
#define MPDC_CRYPTO_H

#include "common.h"
#include "mpdc.h"

/**
 * \file crypto.h
 * \brief MPDC Cryptographic Functions.
 *
 * \details
 * This header defines the cryptographic functions used by the Multi-Party Domain Cryptosystem (MPDC).
 * The crypto module encapsulates all operations required for secure data processing including:
 *
 * - Stream encryption and decryption using a symmetric cipher based on the RCS (Randomized Cipher Stream) algorithm.
 * - Generation of secure key chains by combining a user's password and username with a unique application salt.
 * - Generation of message hashes and message authentication codes (MACs) using SHA3-256 and KMAC256.
 * - Password handling including a minimum quality check, secure password hashing, and verification.
 * - Secure memory management functions to allocate and deallocate memory that is immediately cleared to protect sensitive data.
 *
 * Two configuration macros are provided to tune the passphrase hashing function:
 * - \ref MPDC_CRYPTO_PHASH_CPU_COST sets the CPU cost in iterations.
 * - \ref MPDC_CRYPTO_PHASH_MEMORY_COST sets the memory cost in megabytes.
 *
 * \note
 * These cryptographic operations build upon underlying primitives provided by the QSC library (e.g. SHA3, cSHAKE,
 * KMAC, and RCS). Correct operation of these functions is critical to the security of the MPDC protocol.
 *
 * \test
 * The MPDC crypto functions are rigorously tested to ensure that:
 *
 * - Data streams are properly encrypted and decrypted.
 * - The application key chain is securely generated from a user's password and username, using a salt derived from OS sources.
 * - Message hashes and MAC codes are computed accurately.
 * - Passwords are validated against a set minimum complexity and correctly verified against stored hashes.
 * - Secure memory is allocated and deallocated without leaving residual data.
 *
 * These tests help ensure that the cryptographic foundation of MPDC is robust and reliable.
 */

/*! 
 * \def MPDC_CRYPTO_PHASH_CPU_COST
 * \brief The passphrase hash CPU cost in iterations (acceptable range: 1-100000).
 */
#define MPDC_CRYPTO_PHASH_CPU_COST 4

/*! 
 * \def MPDC_CRYPTO_PHASH_MEMORY_COST
 * \brief The passphrase hash memory cost in MB (acceptable range: 1-4096).
 */
#define MPDC_CRYPTO_PHASH_MEMORY_COST 1

/**
 * \brief Decrypt a stream of bytes.
 *
 * \param output [out] The output array receiving the plain-text.
 * \param seed [in, const] The secret seed array used as the decryption key (expected size: MPDC_CRYPTO_SEED_SIZE).
 * \param input [in, const] The cipher-text input.
 * \param length The number of bytes to decrypt.
 *
 * \return Returns true on success.
 */
MPDC_EXPORT_API bool mpdc_crypto_decrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length);

/**
 * \brief Encrypt a stream of bytes.
 *
 * \param output [out] The output array receiving the cipher-text.
 * \param seed [in, const] The secret seed array used as the encryption key (expected size: MPDC_CRYPTO_SEED_SIZE).
 * \param input [in, const] The plain-text input.
 * \param length The number of bytes to encrypt.
 */
MPDC_EXPORT_API void mpdc_crypto_encrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length);

/**
 * \brief Generate a secure application key chain.
 *
 * Derives a secure key chain (seed) from the provided password and username combined with an
 * application salt generated from OS-specific sources.
 *
 * \param seed [out] The output secret seed array.
 * \param seedlen The length of the seed array.
 * \param password [in, const] The password.
 * \param passlen The byte length of the password.
 * \param username [in, const] The computer's user name.
 * \param userlen The byte length of the user name.
 */
MPDC_EXPORT_API void mpdc_crypto_generate_application_keychain(uint8_t* seed, size_t seedlen, const char* password, size_t passlen, const char* username, size_t userlen);

/**
 * \brief Generate a user-unique application salt from OS sources.
 *
 * The salt is generated by collecting system parameters such as the computer name, user name, and MAC address,
 * and then hashing these values using SHAKE256.
 *
 * \param output [out] The secret seed array to receive the salt.
 * \param outlen The length of the salt array.
 */
MPDC_EXPORT_API void mpdc_crypto_generate_application_salt(uint8_t* output, size_t outlen);

/**
 * \brief Hash a message and write the resulting hash to an output array.
 *
 * Computes the SHA3-256 hash of the specified message.
 *
 * \param output [out] The output array receiving the hash.
 * \param message [in, const] A pointer to the message array.
 * \param msglen The length of the message.
 */
MPDC_EXPORT_API void mpdc_crypto_generate_hash_code(char* output, const char* message, size_t msglen);

/**
 * \brief Compute a MAC (Message Authentication Code) for a message.
 *
 * Uses KMAC256 to compute a MAC from the provided message and key.
 *
 * \param output [out] The output array receiving the MAC.
 * \param outlen The byte length of the output array.
 * \param message [in, const] A pointer to the message array.
 * \param msglen The length of the message.
 * \param key [in, const] A pointer to the key array.
 * \param keylen The length of the key array.
 */
MPDC_EXPORT_API void mpdc_crypto_generate_mac_code(char* output, size_t outlen, const char* message, size_t msglen, const char* key, size_t keylen);

/**
 * \brief Hash a password and user name.
 *
 * Combines the username and password with an application salt to compute a secure hash via KMAC256.
 *
 * \param output [out] The output array receiving the hash.
 * \param outlen The length of the output array.
 * \param username [in, const] The computer's user name.
 * \param userlen The byte length of the user name.
 * \param password [in, const] The password.
 * \param passlen The length of the password.
 */
MPDC_EXPORT_API void mpdc_crypto_hash_password(char* output, size_t outlen, const char* username, size_t userlen, const char* password, size_t passlen);

/**
 * \brief Check a password for a minimum secure threshold.
 *
 * Evaluates the password for minimum requirements (such as inclusion of uppercase, lowercase,
 * numeric, and special characters, and a minimum length).
 *
 * \param password [in, const] The password array.
 * \param passlen The byte length of the password.
 *
 * \return Returns true if the password meets the minimum requirements.
 */
MPDC_EXPORT_API bool mpdc_crypto_password_minimum_check(const char* password, size_t passlen);

/**
 * \brief Verify a password against a stored hash.
 *
 * Computes the hash of the username and password and compares it with a stored hash.
 *
 * \param username [in, const] The computer's user name.
 * \param userlen The byte length of the user name.
 * \param password [in, const] The password.
 * \param passlen The byte length of the password.
 * \param hash The stored hash to compare.
 * \param hashlen The length of the stored hash.
 *
 * \return Returns true if the computed hash matches the stored value.
 */
MPDC_EXPORT_API bool mpdc_crypto_password_verify(const char* username, size_t userlen, const char* password, size_t passlen, const char* hash, size_t hashlen);

/**
 * \brief Allocate a block of secure memory.
 *
 * Allocates memory using secure allocation routines to prevent sensitive data from being paged or left in memory.
 *
 * \param length The number of bytes to allocate.
 *
 * \return Returns a pointer to the allocated secure memory, or NULL on failure.
 */
MPDC_EXPORT_API uint8_t* mpdc_crypto_secure_memory_allocate(size_t length);

/**
 * \brief Release an allocated block of secure memory.
 *
 * Securely erases the memory block and then frees it.
 *
 * \param block The pointer to the memory block.
 * \param length The length of the memory block.
 */
MPDC_EXPORT_API void mpdc_crypto_secure_memory_deallocate(uint8_t* block, size_t length);


#endif
