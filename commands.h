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
* \file commands.h
* \brief The MPDC command enumerations
*/

#ifndef MPDC_COMMANDS_H
#define MPDC_COMMANDS_H

#include "../MPDC/mpdc.h"

/*!
* \enum mpdc_console_commands
* \brief The common console functions
*/
typedef enum mpdc_console_commands
{
	mpdc_commands_none = 0x00,									/*!< No command is recognized */
	mpdc_commands_certificate_create = 0x01,					/*!< Create a new root certificate */
	mpdc_commands_certificate_change = 0x02,					/*!< Broadcast a root certificate change */
	mpdc_commands_certificate_sign = 0x03,						/*!< Sign a device certificate */
	mpdc_commands_certificate_revoke = 0x04,					/*!< Broadcast a certificate revocation */
	mpdc_commands_certificate_format = 0x05,					/*!< Convert a certificate to a readable string */
	mpdc_commands_device_add = 0x06,							/*!< Add a device to the MPDC network */
	mpdc_commands_network_converge = 0x07,						/*!< Broadcast a network reconvergence event */
	mpdc_commands_dla_election = 0x08,							/*!< Broadcast a DLA election */
} mpdc_console_commands;

/*!
* \enum mpdc_application_messages
* \brief The RDS application messages
*/
typedef enum mpdc_application_messages
{
	mpdc_application_not_recognized = 0x00,						/*!< The command was not recognized. */
	mpdc_application_erase_erase_all = 0x01,					/*!< The system will be erased, including configuration and log files, do you want to proceed Y|N */
	mpdc_application_erase_config = 0x02,						/*!< The user configuration will be erased, do you want to proceed Y|N" */
	mpdc_application_erase_log = 0x03,							/*!< The log files will be erased, do you want to proceed Y|N */
	mpdc_application_authorization_failure = 0x04,				/*!< The user is not authorized. Press any key to terminate the application. */
	mpdc_application_retries_exceeded = 0x05,					/*!< Login has exceeded maximum retries. Press any key to terminate the application. */
	mpdc_application_application_quit = 0x06,					/*!< The quit command has been entered. Press any key to terminate the application. */
	mpdc_application_logging_disabled = 0x07,					/*!< Activity logging has been disabled. */
	mpdc_application_logging_enabled = 0x08,					/*!< Activity logging has been enabled. */
	mpdc_application_authentication_failure = 0x09,				/*!< User authentication has failed. Press any key to terminate the application. */
	mpdc_application_operation_aborted = 0x0A,					/*!< The operation was aborted by the user. */
	mpdc_application_system_erased = 0x0B,						/*!< System reset: The application log and configuration have been erased. */
	mpdc_application_configuration_erased = 0x0C,				/*!< System reset: The application log and configuration have been erased. */
	mpdc_application_log_erased = 0x0D,							/*!< The log file has been erased.*/
	mpdc_application_retry_invalid = 0x0E,						/*!< The retry setting is invaid; valid retry range is between one and five [1-5] login attempts. */
	mpdc_application_timeout_invalid = 0x0F,					/*!< The timeout setting is invalid; valid timeout setting is between one and sixty [1-60] minutes. */
	mpdc_application_domain_invalid = 0x10,						/*!< The domain name setting is invalid; valid domain name length is between two and thirty [2-32] characters. */
	mpdc_application_hostname_invalid = 0x11,					/*!< The hostname setting is invalid; valid hostname length is between two and thirty [2-32] characters.*/
	mpdc_application_configuration = 0x12,						/*!< Printing configuration details: */
	mpdc_application_connection = 0x13,							/*!< Printing connection details: */
	mpdc_application_connection_details = 0x14,					/*!<  minutes */
	mpdc_application_log_empty = 0x15,							/*!< The log file is empty.*/
	mpdc_application_first_login = 0x16,						/*!< Running for the first time; please set the applications device name, username and password. */
	mpdc_application_choose_name = 0x17,						/*!< Please choose a user name, minimum 6 characters, to a maximum 128 characters. */
	mpdc_application_choose_password = 0x18,					/*!< Password must be 8-128 characters long [a-z, A-Z], at least 1 number, and 1 symbol [0-9][!#$&'()*+,_./]. */
	mpdc_application_password_set = 0x19,						/*!< The user name and password have been set. */
	mpdc_application_challenge_user = 0x1A,						/*!< Please enter the user name: */
	mpdc_application_challenge_user_failure = 0x1B,				/*!< The user name entered is not recognized. */
	mpdc_application_challenge_password = 0x1C,					/*!< Please enter the password: */
	mpdc_application_challenge_password_failure = 0x1D,			/*!< The password entered is invalid. */
	mpdc_application_challenge_device_name = 0x1E,				/*!< Please enter the device name, minimum 2 characters, to a maximum of 16 characters */
	mpdc_application_challenge_device_name_success = 0x1F,		/*!< The device name has been set. */
	mpdc_application_challenge_device_name_failure = 0x20,		/*!< The device name is invalid. */
	mpdc_application_remote_connect = 0x21,						/*!< Enter the IPv4 or IPv6 address of the host name. */
	mpdc_application_remote_connect_key = 0x22,					/*!< No public key is associated with that address. Enter the encoded public key. */
	mpdc_application_remote_connect_success = 0x23,				/*!< Connecting to the server... */
	mpdc_application_remote_connect_failure = 0x24,				/*!< Connection attempt failed. The server is unreachable. */
	mpdc_application_socket_listen = 0x25,						/*!< The host has entered server mode. Type quit to exit server mode. */
	mpdc_application_socket_listen_failure = 0x26,				/*!< The listener failed to initialize. The host could not enter the listening state. */
	mpdc_application_socket_listen_success = 0x27,				/*!< The listener has initialized: The server is now in the listening state. */
	mpdc_application_generate_key = 0x28,						/*!< Generating the public/private signature key-pair. */
	mpdc_application_generate_key_failure = 0x29,				/*!< The certificate could not be generated. */
	mpdc_application_generate_key_success = 0x2A,				/*!< The public key was saved to: */
	mpdc_application_generate_key_overwrite = 0x2B,				/*!< The signature key-pair already exists, do you want to overwite it? Y|N */
	mpdc_application_operation_cancelled = 0x2C,				/*!< The operation was cancelled by the user. */
	mpdc_application_client_enter_pubkey_path = 0x2D,			/*!< Enter the path to the remote hosts public key. */
	mpdc_application_client_pubkey_path_invalid = 0x2E,			/*!< Invalid path, could not find the hosts public key. */
	mpdc_application_client_connection_success = 0x2F,			/*!< Client connected to the remote host successfully. */
	mpdc_application_client_connection_failure = 0x30,			/*!< Connection attempt failed! Could not connect to the remote server. */
	mpdc_application_address_invalid_format = 0x31,				/*!< The IP address format was invalid! Enter a valid address format, ex. n.n.n.n */
	mpdc_application_certificate_exists = 0x32,					/*!< Warning! The root certificate exists, do you want to overwite it? Y|N */
	mpdc_application_certificate_not_revoked = 0x33,			/*!< Cannot delete an active certificate; revoke the certificate before deleting the file. */
	mpdc_application_console_timeout_expired = 0x34,			/*!< The console timeout period has expired, set to user mode. */
	mpdc_application_challenge_root_path = 0x35,				/*!< Enter the full path to the RDS root certificate. */
	mpdc_application_challenge_root_path_success = 0x36,		/*!< The root certificate has been stored successfully. */
	mpdc_application_challenge_root_path_failure = 0x37,		/*!< Could not find the certificate, or the file is invalid, please enter the path again. */
	mpdc_application_root_copy_success = 0x38,					/*!< The root certificate has been copied successfully.*/
	mpdc_application_root_copy_failure = 0x39,					/*!< The root certificate could not be copied, check the path and permissions. */
	mpdc_application_root_sign_failure = 0x3A,					/*!< The certificate signing failed. The certificate was invalid or has incompatible parameters. */
	mpdc_application_root_sign_success = 0x3B,					/*!< The certificate was signed successfully. */
	mpdc_application_invalid_input = 0x3C,						/*!< The command input was invalid, operation failed. */
	mpdc_application_register_failure = 0x3D,					/*!< The network join request has failed, check the address. */
	mpdc_application_register_success = 0x3E,					/*!< The network join request has succeeded. */
	mpdc_application_register_existing = 0x3F,					/*!< The node is joined to an existing network, rejoin the dla? Y|N */
	mpdc_application_announce_failure = 0x40,					/*!< The certificate has been announced to the network. */
	mpdc_application_announce_success = 0x41,					/*!< The certificate announce operation has failed, check the path. */
	mpdc_application_converge_failure = 0x42,					/*!< The topology update has failed, memory or signing failure. */
	mpdc_application_converge_success = 0x43,					/*!< The topology update has been announced to the network. */
	mpdc_application_message_time_invalid = 0x44,				/*!< The network time is invalid or has substantial delay. */
	mpdc_application_certificate_not_found = 0x45,				/*!< The root, dla, or agent certificate could not be found. */
	mpdc_application_signature_failure = 0x46,					/*!< The signature could not be generated for a message. */
	mpdc_application_network_resign_failure = 0x47,				/*!< The network resign has failed, check the address. */
	mpdc_application_network_resign_success = 0x48,				/*!< This node has resigned from the network. */
	mpdc_application_certificate_revoke_failure = 0x49,			/*!< The certificate revocation has failed, check the path. */
	mpdc_application_certificate_revoke_success = 0x4A,			/*!< The certificate revocation has been broadcast to the network. */
	mpdc_application_address_change_failure = 0x4B,				/*!< The address is not routable, or not properly formed. */
	mpdc_application_address_change_success = 0x4C,				/*!< The server ip address has been changed, restart the server for changes to take effect. */
	mpdc_application_address_change_challenge = 0x4D,			/*!< Do you want to change the ip address? Y|N */
	mpdc_application_address_change_current = 0x4E,				/*!< The auto-detected ip address is:  */
	mpdc_application_address_change_message = 0x4F,				/*!< Enter a routable IPv4 or IPv6 address. */
	mpdc_application_server_service_start_failure = 0x50,		/*!< The server service could not be started, check for a valid signed certificate and network membership. */
	mpdc_application_server_service_start_success = 0x51,		/*!< The server service was started successfully. */
	mpdc_application_server_service_stopped = 0x52,				/*!< The server service has been stopped, use the command 'service start' to run. */
	mpdc_application_server_service_paused = 0x53,				/*!< The server service has been paused, use the command 'service resume' to restart. */
	mpdc_application_server_service_resume_failure = 0x54,		/*!< The server service could not be resumed, use the command 'service start' to run. */
	mpdc_application_server_service_resume_success = 0x55,		/*!< The server service has resumed successfully. */
	mpdc_application_import_certificate_exists = 0x56,			/*!< The server certificate already exists, do you want to replace it? Y|N */
	mpdc_application_import_certificate_changed = 0x57,			/*!< Changing the server name or the domain name requires recreating the certificate, do you want to proceed? Y|N */
	mpdc_application_import_certificate_failure = 0x58,			/*!< The server certificate could not be updated, check the path and root signature */
	mpdc_application_import_certificate_success = 0x59,			/*!< The server certificate was updated successfully */
	mpdc_application_export_certificate_failure = 0x5A,			/*!< The server certificate could not be exported, check the path */
	mpdc_application_export_certificate_success = 0x5B,			/*!< The server certificate was exported successfully */
	mpdc_application_server_domain_change_challenge = 0x5C,		/*!< Do you want to change the servers domain name? Y|N */
	mpdc_application_server_domain_change_current = 0x5D,		/*!< The current domain name string:  */
	mpdc_application_server_domain_change_failure = 0x5E,		/*!< The server could not update the domain name. */
	mpdc_application_server_domain_change_success = 0x5F,		/*!< The domain name has been updated successfully. */
	mpdc_application_certificate_period_update = 0x60,			/*!< The days entered exceeds the root expiration period; days reduced to: */
	mpdc_application_certificate_root_validate = 0x61,			/*!< The certificate must be signed by the RDS server before joining the network. */
	mpdc_application_command_not_supported = 0x62,				/*!< The command is not supported on this server or version. */
	mpdc_application_network_ip_address_not_set = 0x63,			/*!< The network address is invalid or not set. */
	mpdc_application_network_local_error = 0x64,				/*!< received a network error from remote host:  */
	mpdc_application_network_remote_error = 0x65,				/*!< a network error occured with remote host:  */
	mpdc_application_topological_query_unknown = 0x66,			/*!< The query name format is invalid, valid format is domain.client */
	mpdc_application_topological_query_failure = 0x67,			/*!< The device is offline or unknown to the DLA */
	mpdc_application_topological_query_success = 0x68,			/*!< The device is online and available for connection */
	mpdc_application_dla_certificate_path_failure = 0x69,		/*!< The certificate was not found or is not signed */
	mpdc_application_dla_certificate_path_success = 0x6A,		/*!< Provide the full path to the signed DLA certificate */
	mpdc_application_dla_certificate_address_challenge = 0x6B,	/*!< Provide the IP address of the DLA server */
	mpdc_application_dla_certificate_address_failure = 0x6C,	/*!< The DLA IP address format is invalid */
	mpdc_application_server_backup_restore_challenge = 0x6D,	/*!< Restore the configuration files from the last backup? */
	mpdc_application_server_backup_save_confirmation = 0x6E,	/*!< The configuration files have been backed up. */
	mpdc_application_certificate_remote_sign_failure = 0x6F,	/*!< The proxy service could not sign the certificate. */
	mpdc_application_certificate_remote_sign_success = 0x70,	/*!< The certificate was signed by the proxy service. */
	mpdc_application_log_address_change = 0x71,					/*!< The server address has been changed by the administrator */
	mpdc_application_log_domain_change = 0x72,					/*!< The domain name was changed to */
	mpdc_application_log_hostname_change = 0x73,				/*!< The host name was changed to */
	mpdc_application_log_user_logged_in = 0x74,					/*!< Local user logged in: */
	mpdc_application_log_log_created = 0x75,					/*!< Log file created: */
	mpdc_application_log_log_disabled = 0x76,					/*!< Logging has been disabled on */
	mpdc_application_log_log_enabled = 0x77,					/*!< Logging has been enabled on */
	mpdc_application_log_log_header = 0x78,						/*!< MPDC version 1.0a, created September 2022. */
	mpdc_application_log_retries_change = 0x79,					/*!< The login retries setting was changed to */
	mpdc_application_log_timeout_change = 0x7A,					/*!< The session timeout was changed to */
	mpdc_application_log_user_added = 0x7B,						/*!< Added user configuration: */
	mpdc_application_log_state_restore = 0x7C,					/*!< The server state has been restored */
	mpdc_application_log_state_backup = 0x7D,					/*!< The server state has been backed up */
	mpdc_application_log_service_paused = 0x7E,					/*!< The server service was paused */
	mpdc_application_log_service_resumed = 0x7F,				/*!< The server service was resumed */
	mpdc_application_log_service_started = 0x80,				/*!< The server service was started */
	mpdc_application_log_service_stopped = 0x81,				/*!< The server service was stopped */
	mpdc_application_log_mfk_exchange_failure = 0x82,			/*!< The network mfk exchange has failed */
	mpdc_application_log_mfk_exchange_success = 0x83,			/*!< The network mfk exchange has succeeded */
	mpdc_application_log_generate_delete = 0x84,				/*!< The server generated a replacement certificate: */
	mpdc_application_log_generate_failure = 0x85,				/*!< The certificate generation has failed. */
	mpdc_application_log_generate_success = 0x86,				/*!< The certificate generation has succeeded: */
	mpdc_application_log_revocation_failure = 0x87,				/*!< The certificate announcement has succeeded */
	mpdc_application_log_revocation_success = 0x88,				/*!< The certificate revocation has failed */
	mpdc_application_log_convergence_failure = 0x89,			/*!< The converce call has returned a failure */
	mpdc_application_log_convergence_success = 0x8A,			/*!< The remote host has converged and updated its certificate */
	mpdc_application_log_incremental_failure = 0x8B,			/*!< The topological update request failed or was denied */
	mpdc_application_log_incremental_success = 0x8C,			/*!< The topological update request was sent */
	mpdc_application_log_allocation_failure = 0x8D,				/*!< Memory allocation failure, connection aborted to host */
	mpdc_application_log_connection_terminated = 0x8E,			/*!< Connection terminated by remote host */
	mpdc_application_log_configuration_erased = 0x8F,			/*!< The configuration was erased by user: */
	mpdc_application_log_receive_failure = 0x90,				/*!< The network session has timed out */
	mpdc_application_log_register_failure = 0x91,				/*!< The network dla join request was denied */
	mpdc_application_log_register_success = 0x92,				/*!< The network dla join request has succeeded */
	mpdc_application_log_fragment_exchange_failure = 0x93,		/*!< The key fragment exchange has failed */
	mpdc_application_log_fragment_exchange_success = 0x94,		/*!< The key fragment exchange has succeeded */
	mpdc_application_log_local_resign_failure = 0x95,			/*!< The host resignation from the network failed */
	mpdc_application_log_local_resign_success = 0x96,			/*!< The host has resigned from the network */
	mpdc_application_log_remote_invalid_request = 0x97,			/*!< The remote device sent an invalid or unknown request */
	mpdc_application_log_remote_reported_error = 0x98,			/*!< The remote device responded with an error code */
	mpdc_application_log_connect_failure = 0x99,				/*!< Remote connection failed at */
	mpdc_application_log_connect_success = 0x9A,				/*!< Connected to remote host: */
	mpdc_application_log_topology_node_query_failure = 0x9B,	/*!< The node query failed */
	mpdc_application_log_topology_node_query_success = 0x9C,	/*!< The device answered a node query successfully */
	mpdc_application_log_announce_failure = 0x9D,				/*!< The node was not found in the topological database */
	mpdc_application_log_announce_success = 0x9E,				/*!< The certificate announcement has failed */
	mpdc_application_log_remote_signing_failure = 0x9F,			/*!< The remote certificate could not be signed */
	mpdc_application_log_remote_signing_success = 0xA0,			/*!< The remote certificate was signed successfully */
	mpdc_application_log_remote_resign_failure = 0xA1,			/*!< The remote host resignation from the network failed */
	mpdc_application_log_remote_resign_success = 0xA2,			/*!< The remote host has resigned from the network */
	mpdc_application_log_converge_node_remove_challenge = 0xA3,	/*!< Do you want to revoke this device and remove it from the database? */
	mpdc_application_rds_certificate_address_challenge = 0xA4,	/*!< Provide the IP address of the RDS server */
	mpdc_application_rds_certificate_address_failure = 0xA5,	/*!< The RDS IP address format is invalid */
	mpdc_application_server_service_not_started = 0xA6,			/*!< The server service must be started before issuing this command */
} mpdc_application_messages;

/*!
* \enum mpdc_command_actions
* \brief The RDS command actions
*/
typedef enum mpdc_command_actions
{
	mpdc_command_action_none = 0x00,							/*!< unknown command */
	  
	/* configuration commands */
	mpdc_command_action_config_address = 0x01,					/*!< address [ip address] -Assign the server's network interface address; requires a restart.*/
	mpdc_command_action_config_certificate = 0x02,				/*!< crypto -enter the cryptographic command interface */
	mpdc_command_action_config_clear_all = 0x03,				/*!< clear all -requires auth challenge, deletes everything */
	mpdc_command_action_config_clear_config = 0x04,				/*!< clear config -requires auth challenge, deletes public key cache */
	mpdc_command_action_config_clear_log = 0x05,				/*!< clear log -requires auth challenge, clears the logs */
	mpdc_command_action_config_exit = 0x06,						/*!< exit -exits to enable mode */
	mpdc_command_action_config_help = 0x07,						/*!< help for config mode */
	mpdc_command_action_config_log_host = 0x08,					/*!< log [enable | disable] -log command and connection activity */
	mpdc_command_action_config_name_domain = 0x09,				/*!< name domain [domain-name] -fully qualified domain-name */
	mpdc_command_action_config_name_host = 0x0A,				/*!< name host [host-name] */
	mpdc_command_action_config_retries = 0x0B,					/*!< retries [count] -authentication retries, default is 2 */
	mpdc_command_action_config_server = 0x0C,					/*!< server -enter server configuration mode */
	mpdc_command_action_config_timeout = 0x0D,					/*!< timeout [seconds] -session default 120 */

	/* enable commands */
	mpdc_command_action_enable_clear_screen = 0x0E,				/*!< clear the screen */
	mpdc_command_action_enable_config = 0x0F,					/*!< config -enter configuration mode */
	mpdc_command_action_enable_exit = 0x10,						/*!< exit -exits to user mode */
	mpdc_command_action_enable_help = 0x11,						/*!< help for enable mode */
	mpdc_command_action_enable_quit = 0x12,						/*!< quit -closes the application */
	mpdc_command_action_enable_show_config = 0x13,				/*!< show config -show configuration */
	mpdc_command_action_enable_show_log = 0x14,					/*!< show user log -show the user activity log */

	/* user commands */
	mpdc_command_action_user_enable = 0x15,						/*!< enable -triggers authentication challenge */
	mpdc_command_action_user_help = 0x16,						/*!< help -lists the help for user commands */
	mpdc_command_action_user_quit = 0x17,						/*!< quit -closes the application */

	/* config-certificate commands */
	mpdc_command_action_certificate_exit = 0x18,				/*!< exit -exits to config mode */
	mpdc_command_action_certificate_export = 0x19,				/*!< export [path] -exports the local certificate to a file */
	mpdc_command_action_certificate_generate = 0x1A,			/*!< generate [period] -generate the public certificate */
	mpdc_command_action_certificate_help = 0x1B,				/*!< help -command help for certificate mode */
	mpdc_command_action_certificate_import = 0x1C,				/*!< import [path] -imports a certificate from a file */
	mpdc_command_action_certificate_print = 0x1D,				/*!< print -print a certificate */

	/* config-server commands */
	mpdc_command_action_server_backup = 0x1E,					/*!< backup -save a backup of the agent state */
	mpdc_command_action_server_connect = 0x1F,					/*!< connect [ip address] -connects to an application server or client */
	mpdc_command_action_server_exit = 0x20,						/*!< exit -exits to config mode */
	mpdc_command_action_server_help = 0x21,						/*!< help -command help for server mode */
	mpdc_command_action_server_list = 0x22,						/*!< list -display the topological database */
	mpdc_command_action_server_register = 0x23,					/*!< register [address] -register agent with the DLA */
	mpdc_command_action_server_resign = 0x24,					/*!< resign [address] -resign from the DLA */
	mpdc_command_action_server_restore = 0x25,					/*!< restore -restore the device state from backup */
	mpdc_command_action_server_service = 0x26,					/*!< service -[start | stop | pause | resume] the server service */

	/* client config-connect commands */
	mpdc_command_action_server_query = 0x27,					/*!< query [canonical-name] -Request node information for a device from the DLA */
	mpdc_command_action_client_connect_help = 0x28,				/*!< help -command help for connect mode */
	mpdc_command_action_client_connect_quit = 0x29,				/*!< quit -quits the remote server connection */

	/* dla config-certificate commands */
	mpdc_command_action_dla_certificate_revoke = 0x2A,			/*!< revoke [certificate path] -revoke the local device certificate */

	/* dla config-server commands */
	mpdc_command_action_dla_server_announce = 0x2B,				/*!< announce [certificate-path, ip-address] -announce an agent to servers in the network */
	mpdc_command_action_dla_server_converge = 0x2C,				/*!< converge -announce a topology update to the network */
	mpdc_command_action_dla_server_revoke = 0x2D,				/*!< revoke [certificate path] -revoke an agent's credentials by announcing it to the network */
	mpdc_command_action_dla_server_sproxy = 0x2E,				/*!< sproxy [certificate path] -send a remote certificate signing request to the RDS server */

	/* rds config-certificate commands */
	mpdc_command_action_certificate_sign = 0x2F,				/*!< sign [certificate path] -sign a child certificate */

	/* config sub commands */
	mpdc_command_action_config_clear = 0x30,					/*!< clear the configuration */
	mpdc_command_action_config_log = 0x31,						/*!< print the configuration log */
	mpdc_command_action_config_name = 0x32,						/*!< get the configuration name */
	mpdc_command_action_help_enable_all = 0x33,					/*!< enable all mode help */
	mpdc_command_action_help_enable_show = 0x34,				/*!< enable show mode help */
	mpdc_command_action_help_enable_user = 0x35,				/*!< enable user mode help */
	mpdc_command_action_command_unrecognized = 0x36,			/*!< the command was unrecognized */
} mpdc_command_actions;

/*!
* \enum mpdc_console_modes
* \brief The RDS console modes
*/
typedef enum mpdc_console_modes
{
	mpdc_console_mode_name = 0x00,								/*!< The name prompt */
	mpdc_console_mode_user = 0x01,								/*!< The user mode prompt */
	mpdc_console_mode_enable = 0x02,							/*!< The enable mode prompt */
	mpdc_console_mode_config = 0x03,							/*!< The config mode prompt */
	mpdc_console_mode_certificate = 0x04,						/*!< The certificate mode prompt */
	mpdc_console_mode_server = 0x05,							/*!< The server mode prompt */
	mpdc_console_mode_login_message = 0x06,						/*!< The login message */
	mpdc_console_mode_login_password = 0x07,					/*!< The login password message */
	mpdc_console_mode_login_user = 0x08,						/*!< The login user name message */
	mpdc_console_mode_login_hostname = 0x09,					/*!< The login host name message */
	mpdc_console_mode_login_address = 0x0A,						/*!< The login address message */
	mpdc_console_mode_login_domain = 0x0B,						/*!< The login domain name message */
	mpdc_console_mode_login_rootpath = 0x0C,					/*!< The login root path message */
	mpdc_console_mode_client_connected = 0x0D,					/*!< The client is connected to a remore server */
} mpdc_console_modes;

#endif