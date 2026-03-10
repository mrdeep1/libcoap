/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_oscore.h -- Object Security for Constrained RESTful Environments
 *                  (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2026 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore.h
 * @brief CoAP OSCORE support
 */

#ifndef COAP_OSCORE_H_
#define COAP_OSCORE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup application_api
 * @defgroup oscore OSCORE Support
 * API functions for interfacing with OSCORE (RFC8613)
 * @{
 */

/**
 * Callback function type for overriding oscore_find_context().
 *
 * If set via coap_oscore_set_find_func(), this function is
 * called instead of the built-in oscore_find_context() to locate the OSCORE
 * recipient and security context for an incoming request.
 *
 * @param c_context  The CoAP context to search.
 * @param rcpkey_id  The Recipient kid.
 * @param ctxkey_id  The ID Context to match (or NULL if no check).
 * @param oscore_r2  Partial id_context to match against, or NULL.
 * @param recipient_ctx Updated to the matched recipient context on success.
 * @param app_data   The application-specific pointer set alongside the callback.
 *
 * @return The OSCORE context with @p recipient_ctx updated, or NULL if not found.
 */
typedef coap_oscore_recipient_ctx_t *(*coap_oscore_find_func_t)(
    const coap_context_t *c_context,
    const coap_bin_const_t rcpkey_id,
    const coap_bin_const_t ctxkey_id,
    void *app_data);

/**
 * Retrieve the first stored oscore context.
 *
 * @param c_context The CoAP contetx to retreive the first context.
 * @return coap_oscore_ctx_t * retrieve reference to the first oscore context.
 */
COAP_API coap_oscore_ctx_t * coap_oscore_get_first(
    const coap_context_t *c_context
);

/**
 * Retrieve the oscore recipient by key id and context id.
 *
 * @param current_ctx Current oscore context to find next match.
 * @param rcpkey_id The Recipient kid.
 * @param ctxkey_id The ID Context to match.
 */
COAP_API coap_oscore_ctx_t * coap_oscore_get_next(
    coap_oscore_ctx_t * current_ctx,
    const coap_bin_const_t ctxkey_id
);

/**
 * Create the oscore context from the oscore configuration.
 *
 * @param oscore_conf The oscore configuration to create the context from. Ownership of this structure is 
 *                    transferred to this function and will be freed by it.
 * @return coap_oscore_ctx_t * the created oscore context or NULL if failed.
 */
COAP_API coap_oscore_ctx_t * coap_init_oscore_context_from_conf(
    coap_oscore_conf_t *oscore_conf
);

/**
 * Add an OSCORE context to the CoAP context.
 * 
 * @param context The CoAP context to add the OSCORE context to.
 * @param osc_ctx The OSCORE context to add. Ownership of this structure is transferred to
 *                the coap context. On failure, the context is freed.
 * @return int @c 1 if the context was added successfully,
 *             @c 0 otherwise if the provided @p osc_ctx was NULL.
 * 
 * @warning The OSCORE context memory ownership is transfered to libcoap and should not
 *          be released outside.
 */
COAP_API int coap_add_oscore_context(
    coap_context_t *context,
    coap_oscore_ctx_t *osc_ctx
);

/**
 * Remove an OSCORE context from the CoAP context.
 * 
 * @param context The CoAP context to remove the OSCORE context from.
 * @param osc_ctx The OSCORE context to remove. Ownership of this structure is transferred back to
 *                the caller. On failure, the context is not removed.
 * @return int @c 1 if the context was removed successfully, @c 0 otherwise if the context was not attached.
 *             @c 2 if the context is currently used by one or more coap session and will be removed when the 
 *             session(s) are released.
 */
COAP_API int coap_delete_oscore_context(
    coap_context_t *context,
    coap_oscore_ctx_t *osc_ctx
);

/**
 * Creates a new client session to the designated server, protecting the data
 * using OSCORE.
 *
 * @deprecated Use coap_new_client_session_oscore3() instead.
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL
 *                 to let the operating system choose a suitable local
 *                 interface. If an address is specified, the port number
 *                 should be zero, which means that a free port is
 *                 automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto  CoAP Protocol.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore(coap_context_t *ctx,
                                                        const coap_address_t *local_if,
                                                        const coap_address_t *server,
                                                        coap_proto_t proto,
                                                        coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server, protecting the data
 * using OSCORE, along with app_data information (as per coap_session_set_app_data2())
 * and optional WebSockets host (as per coap_ws_set_host_request()) to remove timing
 * window call-back in startup instead of doing
 *   coap_new_client_session_oscore();
 *   coap_session_set_app_data2();
 * or
 *   coap_new_client_session_oscore();
 *   coap_ws_set_host_request();
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL
 *                 to let the operating system choose a suitable local
 *                 interface. If an address is specified, the port number
 *                 should be zero, which means that a free port is
 *                 automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto  CoAP Protocol.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 * @param app_data The pointer to the application data to store or NULL.
 * @param callback The optional release call-back for app_data on session
 *                 removal or NULL.
 * @param ws_host If proto is COAP_PROTO_WS or COAP_PROTO_WSS, then set the
 *                Host parameter accordingly.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore3(coap_context_t *ctx,
                                                         const coap_address_t *local_if,
                                                         const coap_address_t *server,
                                                         coap_proto_t proto,
                                                         coap_oscore_conf_t *oscore_conf,
                                                         void *app_data,
                                                         coap_app_data_free_callback_t callback,
                                                         coap_str_const_t *ws_host);

/**
 * Creates a new client session to the designated server with PSK credentials
 * as well as protecting the data using OSCORE.
 *
 * @deprecated Use coap_new_client_session_oscore_psk3() instead.
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param psk_data PSK parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                                            const coap_address_t *local_if,
                                                            const coap_address_t *server,
                                                            coap_proto_t proto,
                                                            coap_dtls_cpsk_t *psk_data,
                                                            coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server, with PSK credentials
 * protecting the data using OSCORE, along with app_data information (as per
 * coap_session_set_app_data2()) and optional WebSockets host (as per
 * coap_ws_set_host_request()) to remove timing window call-back in (D)TLS startup
 * instead of doing
 *   coap_new_client_session_oscore_psk();
 *   coap_session_set_app_data2();
 * or
 *   coap_new_client_session_oscore_psk();
 *   coap_ws_set_host_request();
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param psk_data PSK parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 * @param app_data The pointer to the application data to store or NULL.
 * @param callback The optional release call-back for app_data on session
 *                 removal or NULL.
 * @param ws_host If proto is COAP_PROTO_WS or COAP_PROTO_WSS, then set the
 *                Host parameter accordingly.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_psk3(coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto,
    coap_dtls_cpsk_t *psk_data,
    coap_oscore_conf_t *oscore_conf,
    void *app_data,
    coap_app_data_free_callback_t callback,
    coap_str_const_t *ws_host);

/**
 * Creates a new client session to the designated server with PKI credentials
 * as well as protecting the data using OSCORE.
 *
 * @deprecated Use coap_new_client_session_oscore_pki3() instead.
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param pki_data PKI parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                                            const coap_address_t *local_if,
                                                            const coap_address_t *server,
                                                            coap_proto_t proto,
                                                            coap_dtls_pki_t *pki_data,
                                                            coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server, with PKI credentials
 * protecting the data using OSCORE, along with app_data information (as per
 * coap_session_set_app_data2()) and optional WebSockets host (as per
 * coap_ws_set_host_request()) to remove timing window call-back in (D)TLS startup
 * instead of doing
 *   coap_new_client_session_oscore_pki();
 *   coap_session_set_app_data2();
 * or
 *   coap_new_client_session_oscore_pki();
 *   coap_ws_set_host_request();
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param pki_data PKI parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 * @param app_data The pointer to the application data to store or NULL.
 * @param callback The optional release call-back for app_data on session
 *                 removal or NULL.
 * @param ws_host If proto is COAP_PROTO_WS or COAP_PROTO_WSS, then set the
 *                Host parameter accordingly.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_pki3(coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto,
    coap_dtls_pki_t *pki_data,
    coap_oscore_conf_t *oscore_conf,
    void *app_data,
    coap_app_data_free_callback_t callback,
    coap_str_const_t *ws_host);
/**
 * Set the context's default OSCORE configuration for a server.
 *
 * @param context     The current coap_context_t object.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return @c 1 if successful, else @c 0.
 */
COAP_API int coap_context_oscore_server(coap_context_t *context,
                                        coap_oscore_conf_t *oscore_conf);

/**
 * Definition of the function used to save the current Sender Sequence Number
 *
 * @param sender_seq_num The Sender Sequence Number to save in non-volatile
 *                      memory.
 * @param param The save_seq_num_func_param provided to
 *              coap_new_oscore_context().
 *
 * @return @c 1 if success, else @c 0 if a failure of some sort.
 */
typedef int (*coap_oscore_save_seq_num_t)(uint64_t sender_seq_num, void *param);

/**
 * Parse an OSCORE configuration (held in memory) and populate a OSCORE
 * configuration structure.
 *
 * @param conf_mem    The current configuration in memory.
 * @param save_seq_num_func Function to call to save Sender Sequence Number in
 *                          non-volatile memory, or NULL.
 * @param save_seq_num_func_param Parameter to pass into
 *                          save_seq_num_func() function.
 * @param start_seq_num The Sender Sequence Number to start with following a
 *                      reboot retrieved out of non-volatile menory or 0.
 *
 * @return The new OSCORE configuration. NULL if failed.  It needs to be freed
 *         off with coap_delete_oscore_conf() when no longer required,
 *         otherwise it is freed off when coap_free_context() is called.
 */
coap_oscore_conf_t *coap_new_oscore_conf(coap_str_const_t conf_mem,
                                         coap_oscore_save_seq_num_t save_seq_num_func,
                                         void *save_seq_num_func_param,
                                         uint64_t start_seq_num);

/**
 * Release all the information associated with the OSCORE configuration.
 *
 * @param oscore_conf The OSCORE configuration structure to release.
 *
 * @return @c 1 Successfully removed, else @c 0 not found.
 */
int coap_delete_oscore_conf(coap_oscore_conf_t *oscore_conf);

/**
 * Register a callback to override the built-in OSCORE context lookup.
 *
 * When @p func is non-NULL it is called instead of oscore_find_context() on
 * every incoming protected request. Pass @p func as NULL to restore the
 * default behaviour.
 *
 * @param context   The CoAP context to configure.
 * @param func      Replacement lookup function, or NULL to reset.
 * @param app_data  Application context forwarded as to @p func.
 */
COAP_API void coap_oscore_set_find_func(
    coap_context_t *context,
    coap_oscore_find_func_t func,
    void *app_data);

/**
 * Add in the specific Recipient ID into the OSCORE context (server only).
 * Note: This is only added to the OSCORE context as first defined by
 * coap_new_client_session_oscore*() or coap_context_oscore_server().
 *
 * @param context The CoAP  context to add the OSCORE recipient_id to.
 * @param recipient_id The Recipient ID to add.
 *
 * @return @c 1 Successfully added, else @c 0 there is an issue.
 */
COAP_API int coap_new_oscore_recipient(coap_context_t *context,
                                       coap_bin_const_t *recipient_id);

/**
 * Release all the information associated for the specific Recipient ID
 * (and hence and stop any further OSCORE protection for this Recipient).
 * Note: This is only removed from the OSCORE context as first defined by
 * coap_new_client_session_oscore*() or coap_context_oscore_server().
 *
 * @param context The CoAP  context holding the OSCORE recipient_id to.
 * @param recipient_id The Recipient ID to remove.
 *
 * @return @c 1 Successfully removed, else @c 0 not found.
 */
COAP_API int coap_delete_oscore_recipient(coap_context_t *context,
                                          coap_bin_const_t *recipient_id);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COAP_OSCORE_H */
