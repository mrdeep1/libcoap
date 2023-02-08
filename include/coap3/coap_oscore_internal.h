/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_oscore_internal.h - Object Security for Constrained RESTful Environments
 *                          (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2024 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2024 Jon Shallow <supjps-libcoap:jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore_internal.h
 * @brief CoAP OSCORE internal information
 */

#ifndef COAP_OSCORE_INTERNAL_H_
#define COAP_OSCORE_INTERNAL_H_

#include "oscore/oscore_context.h"

/**
 * @ingroup internal_api
 * @defgroup oscore_internal OSCORE Support
 * Internal API for interfacing with OSCORE (RFC8613)
 * @{
 */

/**
 * The structure used to hold the OSCORE Sender configuration information
 */
struct coap_oscore_snd_conf_t {
  coap_bin_const_t *sender_id;     /**< Sender ID (i.e. local our id) */
#if COAP_OSCORE_GROUP_SUPPORT
  cose_curve_t sign_curve; /**< Set to one of COSE_curve_* */
  /* Group */
  int group_mode;          /**< 1 if group mode supported else 0 */
  /* Pair Wise */
  int pairwise_mode;       /**< 1 if pairwise mode supported else 0 */
  coap_crypto_pub_key_t *gs_public_key;  /**< Sender Public Key (i.e.
                                              local our Key) */
  coap_crypto_pri_key_t *gs_private_key; /**< Private Key for
                                              gs_public_key */
#endif /* COAP_OSCORE_GROUP_SUPPORT */
};

/**
 * The structure used to hold the OSCORE Recipient configuration
 */
struct coap_oscore_rcp_conf_t {
  struct coap_oscore_rcp_conf_t *next_recipient; /**< Used to maintain
                                                      the chain */
  coap_bin_const_t *recipient_id;  /**< Recipient ID (i.e. local our id) */
#if COAP_OSCORE_GROUP_SUPPORT
  coap_crypto_pub_key_t *gr_public_key; /**< Recipient Public Key
                                             (i.e. remote peer Key) */
  cose_curve_t sign_curve; /**< Set to one of COSE_curve_* */
  /* Group */
  int group_mode;          /**< 1 if group mode supported else 0 */
  /* Pair Wise */
  int pairwise_mode;       /**< 1 if pairwise mode supported else 0 */
#endif /* COAP_OSCORE_GROUP_SUPPORT */
};

/**
 * The structure used to hold the OSCORE configuration information
 */
struct coap_oscore_conf_t {
  coap_bin_const_t *master_secret; /**< Common Master Secret */
  coap_bin_const_t *master_salt;   /**< Common Master Salt */
  coap_bin_const_t *id_context;    /**< Common ID context */
  coap_oscore_snd_conf_t *sender;  /**< The sender - i.e. us */
  coap_oscore_rcp_conf_t *recipient_chain; /**< The recipients  as a chain */
  uint32_t replay_window;          /**< Replay window size
                                        Use COAP_OSCORE_DEFAULT_REPLAY_WINDOW */
  uint32_t ssn_freq;               /**< Sender Seq Num update frequency */
  cose_alg_t aead_alg;             /**< Set to one of COSE_ALGORITHM_AES* */
  cose_hkdf_alg_t hkdf_alg;        /**< Set to one of COSE_HKDF_ALG_* */
  uint32_t rfc8613_b_1_2;          /**< 1 if rfc8613 B.1.2 enabled else 0 */
  uint32_t rfc8613_b_2;            /**< 1 if rfc8613 B.2 protocol else 0 */

#if COAP_OSCORE_GROUP_SUPPORT
  coap_bin_const_t *group_name;    /**< The name of the OSCORE group */
  coap_crypto_pub_key_t *gm_public_key; /**< Group Manager Public Key */
  coap_bin_const_t *sign_params; /**< binary CBOR array */
  cose_curve_t ecdh_alg;   /**< Set to one of COSE_curve_* */
  int cred_fmt;            /**< Credentials type format */
  cose_alg_t group_enc_alg; /**< Group Encryption Algorithm */
  cose_alg_t sign_alg;      /**< Signature Algorithm */
  cose_curve_t sign_curve; /**< Set to one of COSE_curve_* */
  coap_bin_const_t *sign_enc_key; /**< Signature Encryption Key */
  cose_curve_t pw_key_agree_alg; /**< Pairwise Agreement Algorithm */
#endif /* COAP_OSCORE_GROUP_SUPPORT */

  /* General Testing */
  uint32_t break_sender_key;     /**< 1 if sender key to be broken, else 0 */
  uint32_t break_recipient_key;  /**< 1 if recipient key to be broken, else 0 */

  /* SSN handling (not in oscore_config[]) */
  coap_oscore_save_seq_num_t save_seq_num_func; /**< Called every seq num
                                                     change */
  void *save_seq_num_func_param; /**< Passed to save_seq_num_func() */
  uint64_t start_seq_num;        /**< Used for ssn_freq updating */
};

typedef enum oscore_partial_iv_t {
  OSCORE_SEND_NO_IV,  /**< Do not send partial IV unless added by a response */
  OSCORE_SEND_PARTIAL_IV /**< Send partial IV with encrypted PDU */
} oscore_partial_iv_t;

/**
 * Encrypts the specified @p pdu when OSCORE encryption is required
 * on @p session. This function returns the encrypted PDU or @c NULL
 * on error.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to encrypt if necessary.
 * @param kid_context Optional kid context to use or NULL.
 * @param send_partial_iv @c OSCORE_SEND_PARTIAL_IV if partial_iv is always to
 *                        be added, else @c OSCORE_SEND_NO_IV if not to be
 *                        added for a response if not required.
 *
 * @return The OSCORE encrypted version of @p pdu, or @c NULL on error.
 */
coap_pdu_t *coap_oscore_new_pdu_encrypted(coap_session_t *session,
                                          coap_pdu_t *pdu,
                                          coap_bin_const_t *kid_context,
                                          oscore_partial_iv_t send_partial_iv);

/**
 * Decrypts the OSCORE-encrypted parts of @p pdu when OSCORE is used.
 * This function returns the decrypted PDU or @c NULL on error.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to decrypt if necessary.
 *
 * @return The decrypted @p pdu, or @c NULL on error.
 */
struct coap_pdu_t *coap_oscore_decrypt_pdu(coap_session_t *session,
                                           coap_pdu_t *pdu);

/**
 * Cleanup all allocated OSCORE information.
 *
 * @param context The context that the OSCORE information is associated with.
 */
void coap_delete_all_oscore(coap_context_t *context);

/**
 * Cleanup all allocated OSCORE association information.
 *
 * @param session The session that the OSCORE associations are associated with.
 */
void coap_delete_oscore_associations(coap_session_t *session);

/**
 * Determine the additional data size requirements for adding in OSCORE.
 *
 * @param session The session that the OSCORE associations are associated with.
 * @param pdu The non OSCORE protected PDU that is going to be used.
 *
 * @return The OSCORE packet size overhead.
 */
size_t coap_oscore_overhead(coap_session_t *session, coap_pdu_t *pdu);

/**
 * Convert PDU to use Proxy-Scheme option if Proxy-Uri option is present
 *
 * @param pdu The PDU to check and update if appropriate.
 *
 * @return @c 1 success, else @c 0 failure.
 */
int coap_rebuild_pdu_for_proxy(coap_pdu_t *pdu);

/**
 * Initiate an OSCORE session
 *
 * @param session The session that the OSCORE associations are associated with.
 * @param oscore_conf The OSCORE configuration.
 *
 * @return @c 1 success, else @c 0 failure.
 */
int coap_oscore_initiate(coap_session_t *session,
                         coap_oscore_conf_t *oscore_conf);

/** @} */

#endif /* COAP_OSCORE_INTERNAL_H */
