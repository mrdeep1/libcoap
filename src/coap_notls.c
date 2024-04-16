/*
 * coap_notls.c -- Stub Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2016      Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_notls.c
 * @brief NoTLS specific interface functions
 */

#include "coap3/coap_internal.h"

#if !defined(COAP_WITH_LIBTINYDTLS) && !defined(COAP_WITH_LIBOPENSSL) && !defined(COAP_WITH_LIBWOLFSSL) && !defined(COAP_WITH_LIBGNUTLS) && !defined(COAP_WITH_LIBMBEDTLS)

int
coap_dtls_is_supported(void) {
  return 0;
}

int
coap_tls_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_psk_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pki_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pkcs11_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_rpk_is_supported(void) {
  return 0;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = 0;
  version.type = COAP_TLS_LIBRARY_NOTLS;
  return &version;
}

int
coap_dtls_context_set_pki(coap_context_t *ctx COAP_UNUSED,
                          const coap_dtls_pki_t *setup_data COAP_UNUSED,
                          const coap_dtls_role_t role COAP_UNUSED
                         ) {
  return 0;
}

int
coap_dtls_context_set_pki_root_cas(coap_context_t *ctx COAP_UNUSED,
                                   const char *ca_file COAP_UNUSED,
                                   const char *ca_path COAP_UNUSED
                                  ) {
  return 0;
}

#if COAP_CLIENT_SUPPORT
int
coap_dtls_context_set_cpsk(coap_context_t *ctx COAP_UNUSED,
                           coap_dtls_cpsk_t *setup_data COAP_UNUSED
                          ) {
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
int
coap_dtls_context_set_spsk(coap_context_t *ctx COAP_UNUSED,
                           coap_dtls_spsk_t *setup_data COAP_UNUSED
                          ) {
  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx COAP_UNUSED) {
  return 0;
}

static coap_log_t dtls_log_level = COAP_LOG_EMERG;

void
coap_dtls_startup(void) {
}

void *
coap_dtls_get_tls(const coap_session_t *c_session COAP_UNUSED,
                  coap_tls_library_t *tls_lib) {
  if (tls_lib)
    *tls_lib = COAP_TLS_LIBRARY_NOTLS;
  return NULL;
}

void
coap_dtls_shutdown(void) {
  coap_dtls_set_log_level(COAP_LOG_EMERG);
}

void
coap_dtls_set_log_level(coap_log_t level) {
  dtls_log_level = level;
}

coap_log_t
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

void *
coap_dtls_new_context(coap_context_t *coap_context COAP_UNUSED) {
  return NULL;
}

void
coap_dtls_free_context(void *handle COAP_UNUSED) {
}

#if COAP_SERVER_SUPPORT
void *
coap_dtls_new_server_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
void *
coap_dtls_new_client_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

void
coap_dtls_free_session(coap_session_t *coap_session COAP_UNUSED) {
}

void
coap_dtls_session_update_mtu(coap_session_t *session COAP_UNUSED) {
}

ssize_t
coap_dtls_send(coap_session_t *session COAP_UNUSED,
               const uint8_t *data COAP_UNUSED,
               size_t data_len COAP_UNUSED) {
  return -1;
}

int
coap_dtls_is_context_timeout(void) {
  return 1;
}

coap_tick_t
coap_dtls_get_context_timeout(void *dtls_context COAP_UNUSED) {
  return 0;
}

coap_tick_t
coap_dtls_get_timeout(coap_session_t *session COAP_UNUSED, coap_tick_t now COAP_UNUSED) {
  return 0;
}

/*
 * return 1 timed out
 *        0 still timing out
 */
int
coap_dtls_handle_timeout(coap_session_t *session COAP_UNUSED) {
  return 0;
}

int
coap_dtls_receive(coap_session_t *session COAP_UNUSED,
                  const uint8_t *data COAP_UNUSED,
                  size_t data_len COAP_UNUSED
                 ) {
  return -1;
}

#if COAP_SERVER_SUPPORT
int
coap_dtls_hello(coap_session_t *session COAP_UNUSED,
                const uint8_t *data COAP_UNUSED,
                size_t data_len COAP_UNUSED
               ) {
  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

unsigned int
coap_dtls_get_overhead(coap_session_t *session COAP_UNUSED) {
  return 0;
}

#if COAP_CLIENT_SUPPORT
void *
coap_tls_new_client_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_tls_new_server_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_tls_free_session(coap_session_t *coap_session COAP_UNUSED) {
}

/*
 * strm
 * return +ve Number of bytes written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_write(coap_session_t *session COAP_UNUSED,
               const uint8_t *data COAP_UNUSED,
               size_t data_len COAP_UNUSED) {
  return -1;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_read(coap_session_t *session COAP_UNUSED,
              uint8_t *data COAP_UNUSED,
              size_t data_len COAP_UNUSED) {
  return -1;
}

#if COAP_SERVER_SUPPORT
typedef struct coap_local_hash_t {
  size_t ofs;
  coap_key_t key[8];   /* 32 bytes in total */
} coap_local_hash_t;

coap_digest_ctx_t *
coap_digest_setup(void) {
  coap_key_t *digest_ctx = coap_malloc_type(COAP_DIGEST_CTX, sizeof(coap_local_hash_t));

  if (digest_ctx) {
    memset(digest_ctx, 0, sizeof(coap_local_hash_t));
  }

  return digest_ctx;
}

void
coap_digest_free(coap_digest_ctx_t *digest_ctx) {
  coap_free_type(COAP_DIGEST_CTX, digest_ctx);
}

int
coap_digest_update(coap_digest_ctx_t *digest_ctx,
                   const uint8_t *data,
                   size_t data_len) {
  coap_local_hash_t *local = (coap_local_hash_t *)digest_ctx;

  coap_hash(data, data_len, local->key[local->ofs]);

  local->ofs = (local->ofs + 1) % 7;
  return 1;
}

int
coap_digest_final(coap_digest_ctx_t *digest_ctx,
                  coap_digest_t *digest_buffer) {
  coap_local_hash_t *local = (coap_local_hash_t *)digest_ctx;

  memcpy(digest_buffer, local->key, sizeof(coap_digest_t));

  coap_digest_free(digest_ctx);
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_WS_SUPPORT || COAP_OSCORE_GROUP_SUPPORT
int
coap_crypto_hash(cose_alg_t alg,
                 const coap_bin_const_t *data,
                 coap_bin_const_t **hash) {
  SHA1Context sha1_context;
  coap_binary_t *dummy = NULL;

  (void)alg;

  SHA1Reset(&sha1_context);
  if (SHA1Input(&sha1_context, data->s, data->length) != shaSuccess)
    return 0;
  dummy = coap_new_binary(SHA1HashSize);
  if (!dummy)
    return 0;
  if (SHA1Result(&sha1_context, dummy->s) != shaSuccess) {
    coap_delete_binary(dummy);
    return 0;
  }
  *hash = (coap_bin_const_t *)(dummy);
  return 1;
}
#endif /* COAP_WS_SUPPORT || COAP_OSCORE_GROUP_SUPPORT */

#if COAP_OSCORE_SUPPORT

int
coap_oscore_is_supported(void) {
  return 0;
}

int
coap_oscore_group_is_supported(void) {
  return 0;
}

int
coap_oscore_pairwise_is_supported(void) {
  return 0;
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  (void)alg;
  return 0;
}

int
coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg) {
  (void)hkdf_alg;
  return 0;
}

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)aad;
  (void)result;
  *max_result_len = 0;
  return 0;
}

int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)aad;
  (void)result;
  *max_result_len = 0;
  return 0;
}

int
coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  (void)hmac_alg;
  (void)key;
  (void)data;
  (void)hmac;
  return 0;
}

#if COAP_OSCORE_GROUP_SUPPORT
int
coap_crypto_check_curve_alg(cose_curve_t alg) {
  (void)alg;
  return 0;
}

int
coap_crypto_read_pem_private_key(const char *filename,
                                 coap_crypto_pri_key_t **private) {
  (void)filename;
  (void)private;
  return 0;
}

int
coap_crypto_read_asn1_private_key(coap_bin_const_t *binary,
                                  coap_crypto_pri_key_t **private) {
  (void)binary;
  (void)private;
  return 0;
}

int
coap_crypto_read_raw_private_key(cose_curve_t curve,
                                 coap_bin_const_t *binary,
                                 coap_crypto_pri_key_t **private) {
  (void)curve;
  (void)binary;
  (void)private;
  return 0;
}

coap_crypto_pri_key_t *
coap_crypto_duplicate_private_key(coap_crypto_pri_key_t *key) {
  (void)key;
  return NULL;
}

void
coap_crypto_delete_private_key(coap_crypto_pri_key_t *key) {
  (void)key;
}

int
coap_crypto_read_pem_public_key(const char *filename,
                                coap_crypto_pub_key_t **public) {
  (void)filename;
  (void)public;
  return 0;
}

int
coap_crypto_read_asn1_public_key(coap_bin_const_t *binary,
                                 coap_crypto_pub_key_t **public) {
  (void)binary;
  (void)public;
  return 0;
}

int
coap_crypto_read_raw_public_key(cose_curve_t curve,
                                coap_bin_const_t *binary,
                                coap_crypto_pub_key_t **public) {
  (void)curve;
  (void)binary;
  (void)public;
  return 0;
}

coap_crypto_pub_key_t *
coap_crypto_duplicate_public_key(coap_crypto_pub_key_t *key) {
  (void)key;
  return NULL;
}

void
coap_crypto_delete_public_key(coap_crypto_pub_key_t *key) {
  (void)key;
}

int
coap_crypto_hash_sign(cose_alg_t hash,
                      coap_binary_t *signature,
                      coap_bin_const_t *text,
                      coap_crypto_pri_key_t *private_key) {
  (void)hash;
  (void)signature;
  (void)text;
  (void)private_key;
  return 0;
}

int
coap_crypto_hash_verify(cose_alg_t hash,
                        coap_binary_t *signature,
                        coap_bin_const_t *text,
                        coap_crypto_pub_key_t *public_key) {
  (void)hash;
  (void)signature;
  (void)text;
  (void)public_key;
  return 0;
}

int
coap_crypto_gen_pkey(cose_curve_t curve,
                     coap_bin_const_t **private,
                     coap_bin_const_t **public) {
  (void)curve;
  (void)private;
  (void)public;
  return 0;
}

int
coap_crypto_derive_shared_secret(cose_curve_t curve,
                                 coap_bin_const_t *raw_local_private,
                                 coap_bin_const_t *raw_peer_public,
                                 coap_bin_const_t **shared_secret) {
  (void)curve;
  (void)raw_local_private;
  (void)raw_peer_public;
  (void)shared_secret;
  return 0;
}

#endif /* COAP_OSCORE_GROUP_SUPPORT */

#endif /* COAP_OSCORE_SUPPORT */

#else /* !COAP_WITH_LIBTINYDTLS && !COAP_WITH_LIBOPENSSL && !COAP_WITH_LIBWOLFSSL && !COAP_WITH_LIBGNUTLS */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* !COAP_WITH_LIBTINYDTLS && !COAP_WITH_LIBOPENSSL && !COAP_WITH_LIBWOLFSSL && !COAP_WITH_LIBGNUTLS && !COAP_WITH_LIBMBEDTLS */
