/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * @file oscore_context.c
 * @brief An implementation of the Object Security for Constrained RESTful
 * Environments (RFC 8613).
 *
 * \author Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 */

#include "coap3/coap_internal.h"

#include <stdio.h>

/* Move ptr from b to a, and then clear b */
#define OSC_MOVE_PTR(a,b) do { (a) = (b); (b) = NULL; } while(0)

static size_t
compose_info(uint8_t *buffer,
             size_t buf_size,
             cose_alg_t alg,
             coap_bin_const_t *id,
             coap_bin_const_t *id_context,
             coap_str_const_t *type,
             size_t out_len) {
  size_t ret = 0;
  size_t rem_size = buf_size;

  ret += oscore_cbor_put_array(&buffer, &rem_size, 5);
  ret += oscore_cbor_put_bytes(&buffer,
                               &rem_size,
                               id ? id->s : NULL,
                               id ? id->length : 0);
  if (id_context != NULL && id_context->length > 0) {
    ret += oscore_cbor_put_bytes(&buffer,
                                 &rem_size,
                                 id_context->s,
                                 id_context->length);
  } else {
    ret += oscore_cbor_put_nil(&buffer, &rem_size);
  }
  ret += oscore_cbor_put_unsigned(&buffer, &rem_size, alg);
  ret += oscore_cbor_put_text(&buffer,
                              &rem_size,
                              (const char *)type->s,
                              type->length);
  ret += oscore_cbor_put_unsigned(&buffer, &rem_size, out_len);
  return ret;
}

#if COAP_OSCORE_GROUP_SUPPORT
int
oscore_derive_keystream(oscore_ctx_t *osc_ctx,
                        cose_encrypt0_t *cose,
                        uint8_t coap_request,
                        coap_bin_const_t *sender_id,
                        coap_bin_const_t *id_context,
                        size_t cs_size,
                        uint8_t *keystream,
                        size_t keystream_size) {
  uint8_t info_buffer[30];
  uint8_t *buffer = info_buffer;
  size_t info_len = 0;
  size_t rem_size = sizeof(info_buffer);
  ;

  info_len += oscore_cbor_put_array(&buffer, &rem_size, 4);
  /* 1. id */
  info_len += oscore_cbor_put_bytes(&buffer,
                                    &rem_size,
                                    sender_id->s,
                                    sender_id->length);
  /* 2. id_context */
  info_len += oscore_cbor_put_bytes(&buffer,
                                    &rem_size,
                                    id_context->s,
                                    id_context->length);
  /* 3. type */
  if (coap_request)
    info_len += oscore_cbor_put_true(&buffer, &rem_size);
  else
    info_len += oscore_cbor_put_false(&buffer, &rem_size);
  /* 4. L */
  info_len += oscore_cbor_put_unsigned(&buffer, &rem_size, cs_size);

  oscore_hkdf(osc_ctx->hkdf_alg,
              &cose->partial_iv,
              osc_ctx->sign_enc_key,
              info_buffer,
              info_len,
              keystream,
              keystream_size);
  return 1;
}
#endif /* COAP_OSCORE_GROUP_SUPPORT */

uint8_t
oscore_bytes_equal(uint8_t *a_ptr,
                   uint8_t a_len,
                   uint8_t *b_ptr,
                   uint8_t b_len) {
  if (a_len != b_len) {
    return 0;
  }

  if (memcmp(a_ptr, b_ptr, a_len) == 0) {
    return 1;
  } else {
    return 0;
  }
}

void
oscore_enter_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx) {
  if (c_context->p_osc_ctx) {
    oscore_ctx_t *prev = c_context->p_osc_ctx;
    oscore_ctx_t *next = c_context->p_osc_ctx->next;

    while (next) {
      prev = next;
      next = next->next;
    }
    prev->next = osc_ctx;
  } else
    c_context->p_osc_ctx = osc_ctx;
}

static void
oscore_free_recipient(oscore_recipient_ctx_t *rcp_ctx) {
  coap_delete_bin_const(rcp_ctx->recipient_id);
  coap_delete_bin_const(rcp_ctx->recipient_key);
#if COAP_OSCORE_GROUP_SUPPORT
  coap_delete_bin_const(rcp_ctx->pw_recipient_key);
  coap_delete_bin_const(rcp_ctx->pw_sender_key);
  coap_crypto_delete_public_key(rcp_ctx->g_public_key);
#endif /* COAP_OSCORE_GROUP_SUPPORT */
  coap_free_type(COAP_OSCORE_REC, rcp_ctx);
}

void
oscore_free_sender(oscore_sender_ctx_t *snd_ctx) {
  if (snd_ctx == NULL)
    return;
  coap_delete_bin_const(snd_ctx->sender_id);
  coap_delete_bin_const(snd_ctx->sender_key);
#if COAP_OSCORE_GROUP_SUPPORT
  coap_crypto_delete_private_key(snd_ctx->g_private_key);
  coap_crypto_delete_public_key(snd_ctx->g_public_key);
#endif /* COAP_OSCORE_GROUP_SUPPORT */
  coap_free_type(COAP_OSCORE_SEN, snd_ctx);
}

void
oscore_free_context(oscore_ctx_t *osc_ctx) {
  if (osc_ctx == NULL)
    return;

  oscore_free_sender(osc_ctx->sender_context);

  while (osc_ctx->recipient_chain) {
    oscore_recipient_ctx_t *next = osc_ctx->recipient_chain->next_recipient;

    oscore_free_recipient(osc_ctx->recipient_chain);
    osc_ctx->recipient_chain = next;
  }

  coap_delete_bin_const(osc_ctx->master_secret);
  coap_delete_bin_const(osc_ctx->master_salt);
  coap_delete_bin_const(osc_ctx->id_context);
  coap_delete_bin_const(osc_ctx->common_iv);
#if COAP_OSCORE_GROUP_SUPPORT
  coap_delete_bin_const(osc_ctx->sign_params);
  coap_delete_bin_const(osc_ctx->sign_enc_key);
#endif /* COAP_OSCORE_GROUP_SUPPORT */
  coap_free_type(COAP_OSCORE_COM, osc_ctx);
}

void
oscore_free_contexts(coap_context_t *c_context) {
  while (c_context->p_osc_ctx) {
    oscore_ctx_t *osc_ctx = c_context->p_osc_ctx;

    c_context->p_osc_ctx = osc_ctx->next;

    oscore_free_context(osc_ctx);
  }
}

int
oscore_remove_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx) {
  oscore_ctx_t *prev = NULL;
  oscore_ctx_t *next = c_context->p_osc_ctx;
  while (next) {
    if (next == osc_ctx) {
      if (prev != NULL)
        prev->next = next->next;
      else
        c_context->p_osc_ctx = next->next;
      oscore_free_context(next);
      return 1;
    }
    prev = next;
    next = next->next;
  }
  return 0;
}

/*
 *  oscore_find_context
 * Finds OSCORE context for rcpkey_id and optional ctxkey_id
 * rcpkey_id can be 0 length.
 * Updates recipient_ctx.
 */
oscore_ctx_t *
oscore_find_context(const coap_context_t *c_context,
                    const coap_bin_const_t rcpkey_id,
                    const coap_bin_const_t *ctxkey_id,
                    uint8_t *oscore_r2,
                    oscore_recipient_ctx_t **recipient_ctx) {
  oscore_ctx_t *pt = c_context->p_osc_ctx;

  *recipient_ctx = NULL;
  assert(rcpkey_id.length == 0 || rcpkey_id.s != NULL);
  while (pt != NULL) {
    int ok = 0;
    oscore_recipient_ctx_t *rpt = pt->recipient_chain;

    while (rpt) {
      ok = 0;
      if (rpt->recipient_id && rcpkey_id.length == rpt->recipient_id->length) {
        if (rcpkey_id.length != 0)
          ok = memcmp(rpt->recipient_id->s, rcpkey_id.s, rcpkey_id.length) != 0;
        if (oscore_r2) {
          if (pt->id_context != NULL && pt->id_context->length > 8) {
            ok = ok + (memcmp(pt->id_context->s, oscore_r2, 8) != 0);
          } else {
            ok += 1;
          }
        } else if (ctxkey_id) {
          if (pt->id_context != NULL) {
            if (ctxkey_id->length != pt->id_context->length)
              ok += 1;
            else
              ok = ok + (memcmp(pt->id_context->s,
                                ctxkey_id->s,
                                ctxkey_id->length) != 0);
          } else if (ctxkey_id->length > 0)
            ok += 1;
        }
        if (ok == 0) {
          /* optional id context and recipient id are the same  */
          *recipient_ctx = rpt;
          return pt; /* OSCORE context found */
        }
      }
      rpt = rpt->next_recipient;
    } /* while rpt */
    pt = pt->next;
  } /* end while */
  return NULL;
}

#define OSCORE_LOG_SIZE 16
void
oscore_log_hex_value(coap_log_t level,
                     const char *name,
                     coap_bin_const_t *value) {
  size_t i;

  if (value == NULL) {
    coap_log(level, "    %-16s\n", name);
    return;
  }
  if (value->length == 0) {
    coap_log(level, "    %-16s <>\n", name);
    return;
  }
  if (coap_get_log_level() >= level) {
    for (i = 0; i < value->length; i += OSCORE_LOG_SIZE) {
      char number[3 * OSCORE_LOG_SIZE + 4];

      oscore_convert_to_hex(&value->s[i],
                            value->length - i > OSCORE_LOG_SIZE ?
                            OSCORE_LOG_SIZE : value->length - i,
                            number,
                            sizeof(number));
      coap_log(level, "    %-16s %s\n", i == 0 ? name : "", number);
    }
  }
}

void
oscore_log_int_value(coap_log_t level, const char *name, int value) {
  coap_log(level, "    %-16s %2d\n", name, value);
}

void
oscore_log_char_value(coap_log_t level, const char *name, const char *value) {
  coap_log(level, "    %-16s %s\n", name, value);
}

void
oscore_convert_to_hex(const uint8_t *src,
                      size_t src_len,
                      char *dest,
                      size_t dst_len) {
  /*
   * Last output character will be '\000'
   * (If output undersized, add trailing ... to indicate this.
   */
  size_t space = (dst_len - 4) / 3;
  uint32_t qq;

  for (qq = 0; qq < src_len && qq < space; qq++) {
    char tmp = src[qq] >> 4;
    if (tmp > 9)
      tmp = tmp + 0x61 - 10;
    else
      tmp = tmp + 0x30;
    dest[qq * 3] = tmp;
    tmp = src[qq] & 0xf;
    if (tmp > 9)
      tmp = tmp + 0x61 - 10;
    else
      tmp = tmp + 0x30;
    dest[qq * 3 + 1] = tmp;
    dest[qq * 3 + 2] = 0x20;
  }
  if (qq != src_len) {
    dest[qq * 3] = '.';
    dest[qq * 3 + 1] = '.';
    dest[qq * 3 + 2] = '.';
    qq++;
  }
  dest[qq * 3] = 0;
}

coap_bin_const_t *
oscore_build_key(oscore_ctx_t *osc_ctx,
                 coap_bin_const_t *salt,
                 coap_bin_const_t *ikm,
                 cose_alg_t alg_aead,
                 coap_bin_const_t *id,
                 coap_str_const_t *type,
                 size_t out_len) {
  uint8_t info_buffer[80];
  size_t info_len;
  coap_bin_const_t *hkdf;
  uint8_t *hkdf_tmp = coap_malloc_type(COAP_STRING, out_len);

  if (hkdf_tmp == NULL)
    return NULL;

  info_len = compose_info(info_buffer,
                          sizeof(info_buffer),
                          alg_aead,
                          id,
                          osc_ctx->id_context,
                          type,
                          out_len);
  if (info_len == 0 || info_len > sizeof(info_buffer)) {
    coap_free_type(COAP_STRING, hkdf_tmp);
    return NULL;
  }

  oscore_hkdf(osc_ctx->hkdf_alg,
              salt,
              ikm,
              info_buffer,
              info_len,
              hkdf_tmp,
              out_len);
  hkdf = coap_new_bin_const(hkdf_tmp, out_len);
  coap_free_type(COAP_STRING, hkdf_tmp);
  return hkdf;
}

static void
oscore_log_context(oscore_ctx_t *osc_ctx, const char *heading) {
#if COAP_MAX_LOGGING_LEVEL < _COAP_LOG_OSCORE
  (void)osc_ctx;
  (void)heading;
#else /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_OSCORE */
  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    char buffer[30];
    oscore_recipient_ctx_t *next = osc_ctx->recipient_chain;
    size_t count = 0;

    coap_log_oscore("%s\n", heading);
    oscore_log_char_value(COAP_LOG_OSCORE, "AEAD alg",
                          cose_get_alg_name(osc_ctx->aead_alg, buffer,
                                            sizeof(buffer)));
    oscore_log_char_value(COAP_LOG_OSCORE, "HKDF alg",
                          cose_get_hkdf_alg_name(osc_ctx->hkdf_alg, buffer,
                                                 sizeof(buffer)));
    oscore_log_hex_value(COAP_LOG_OSCORE, "ID Context", osc_ctx->id_context);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Master Secret",
                         osc_ctx->master_secret);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Master Salt", osc_ctx->master_salt);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Common IV", osc_ctx->common_iv);
#if COAP_OSCORE_GROUP_SUPPORT
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Sign Enc Key",
                         osc_ctx->sign_enc_key);
#endif /* COAP_OSCORE_GROUP_SUPPORT */
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Sender ID",
                         osc_ctx->sender_context->sender_id);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Sender Key",
                         osc_ctx->sender_context->sender_key);
    while (next) {
      snprintf(buffer, sizeof(buffer), "Recipient ID[%zu]", count);
      oscore_log_hex_value(COAP_LOG_OSCORE,
                           buffer,
                           next->recipient_id);
      snprintf(buffer, sizeof(buffer), "Recipient Key[%zu]", count);
      oscore_log_hex_value(COAP_LOG_OSCORE,
                           buffer,
                           next->recipient_key);
      count++;
      next = next->next_recipient;
    }
  }
#endif /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_OSCORE */
}

void
oscore_update_ctx(oscore_ctx_t *osc_ctx, coap_bin_const_t *id_context) {
  coap_bin_const_t *temp;

  /* Update with new ID Context */
  coap_delete_bin_const(osc_ctx->id_context);
  osc_ctx->id_context = id_context;

  /* Update sender_key, recipient_key and common_iv */
  temp = osc_ctx->sender_context->sender_key;
  osc_ctx->sender_context->sender_key =
      oscore_build_key(osc_ctx,
                       osc_ctx->master_salt,
                       osc_ctx->master_secret,
                       osc_ctx->aead_alg,
                       osc_ctx->sender_context->sender_id,
                       coap_make_str_const("Key"),
                       cose_key_len(osc_ctx->aead_alg));
  if (!osc_ctx->sender_context->sender_key)
    osc_ctx->sender_context->sender_key = temp;
  else
    coap_delete_bin_const(temp);
  temp = osc_ctx->recipient_chain->recipient_key;
  osc_ctx->recipient_chain->recipient_key =
      oscore_build_key(osc_ctx,
                       osc_ctx->master_salt,
                       osc_ctx->master_secret,
                       osc_ctx->aead_alg,
                       osc_ctx->recipient_chain->recipient_id,
                       coap_make_str_const("Key"),
                       cose_key_len(osc_ctx->aead_alg));
  if (!osc_ctx->recipient_chain->recipient_key)
    osc_ctx->recipient_chain->recipient_key = temp;
  else
    coap_delete_bin_const(temp);
  temp = osc_ctx->common_iv;
  osc_ctx->common_iv = oscore_build_key(osc_ctx,
                                        osc_ctx->master_salt,
                                        osc_ctx->master_secret,
                                        osc_ctx->aead_alg,
                                        NULL,
                                        coap_make_str_const("IV"),
                                        cose_nonce_len(osc_ctx->aead_alg));
  if (!osc_ctx->common_iv)
    osc_ctx->common_iv = temp;
  else
    coap_delete_bin_const(temp);
#if COAP_OSCORE_GROUP_SUPPORT
  /* Signature Encryption Key */
  temp = osc_ctx->sign_enc_key;
  osc_ctx->sign_enc_key =
      oscore_build_key(osc_ctx,
                       osc_ctx->master_salt,
                       osc_ctx->master_secret,
                       osc_ctx->group_enc_alg,
                       NULL,
                       coap_make_str_const("SEKey"),
                       cose_key_len(osc_ctx->group_enc_alg));
  if (!osc_ctx->sign_enc_key)
    osc_ctx->sign_enc_key = temp;
  else
    coap_delete_bin_const(temp);
#endif /* COAP_OSCORE_GROUP_SUPPORT */

  oscore_log_context(osc_ctx, "Updated Common context");
}

oscore_ctx_t *
oscore_duplicate_ctx(coap_context_t *c_context,
                     oscore_ctx_t *o_osc_ctx,
                     coap_bin_const_t *sender_id,
                     coap_bin_const_t *recipient_id,
                     coap_bin_const_t *id_context) {
  oscore_ctx_t *osc_ctx = NULL;
  oscore_sender_ctx_t *sender_ctx = NULL;
  coap_oscore_rcp_conf_t *rcp_conf;

  osc_ctx = coap_malloc_type(COAP_OSCORE_COM, sizeof(oscore_ctx_t));
  if (osc_ctx == NULL)
    goto error;
  memset(osc_ctx, 0, sizeof(oscore_ctx_t));

  sender_ctx = coap_malloc_type(COAP_OSCORE_SEN, sizeof(oscore_sender_ctx_t));
  if (sender_ctx == NULL)
    goto error;
  memset(sender_ctx, 0, sizeof(oscore_sender_ctx_t));

  osc_ctx->sender_context = sender_ctx;
  if (o_osc_ctx->master_secret)
    osc_ctx->master_secret =
        coap_new_bin_const(o_osc_ctx->master_secret->s,
                           o_osc_ctx->master_secret->length);
  if (o_osc_ctx->master_salt)
    osc_ctx->master_salt = coap_new_bin_const(o_osc_ctx->master_salt->s,
                                              o_osc_ctx->master_salt->length);
  osc_ctx->aead_alg = o_osc_ctx->aead_alg;
  osc_ctx->hkdf_alg = o_osc_ctx->hkdf_alg;
  if (id_context)
    osc_ctx->id_context = coap_new_bin_const(id_context->s, id_context->length);
  osc_ctx->ssn_freq = o_osc_ctx->ssn_freq;
  osc_ctx->replay_window_size = o_osc_ctx->replay_window_size;
  osc_ctx->rfc8613_b_1_2 = o_osc_ctx->rfc8613_b_1_2;
  osc_ctx->rfc8613_b_2 = o_osc_ctx->rfc8613_b_2;
  osc_ctx->save_seq_num_func = o_osc_ctx->save_seq_num_func;
  osc_ctx->save_seq_num_func_param = o_osc_ctx->save_seq_num_func_param;

  if (o_osc_ctx->master_secret) {
    /* sender_ key */
    sender_ctx->sender_key = oscore_build_key(osc_ctx,
                                              osc_ctx->master_salt,
                                              osc_ctx->master_secret,
                                              osc_ctx->aead_alg,
                                              sender_id,
                                              coap_make_str_const("Key"),
                                              cose_key_len(osc_ctx->aead_alg));
    if (!sender_ctx->sender_key)
      goto error;

    /* common IV */
    osc_ctx->common_iv = oscore_build_key(osc_ctx,
                                          osc_ctx->master_salt,
                                          osc_ctx->master_secret,
                                          osc_ctx->aead_alg,
                                          NULL,
                                          coap_make_str_const("IV"),
                                          cose_nonce_len(osc_ctx->aead_alg));
    if (!osc_ctx->common_iv)
      goto error;

#if COAP_OSCORE_GROUP_SUPPORT
    /* Signature Encryption Key */
    osc_ctx->sign_enc_key =
        oscore_build_key(osc_ctx,
                         osc_ctx->master_salt,
                         osc_ctx->master_secret,
                         osc_ctx->group_enc_alg,
                         NULL,
                         coap_make_str_const("SEKey"),
                         cose_key_len(osc_ctx->group_enc_alg));
    if (!osc_ctx->sign_enc_key)
      goto error;
#endif /* COAP_OSCORE_GROUP_SUPPORT */
  }

  /*
   * Need to set the last Sender Seq Num based on ssn_freq
   * The value should only change if there is a change to ssn_freq
   * and (potentially) be lower than seq, then save_seq_num_func() is
   * immediately called on next SSN update.
   */
  sender_ctx->next_seq = 0;
  sender_ctx->seq = 0;

  sender_ctx->sender_id = coap_new_bin_const(sender_id->s, sender_id->length);

  rcp_conf = coap_malloc_type(COAP_STRING, sizeof(coap_oscore_rcp_conf_t));
  if (rcp_conf == NULL)
    goto error;
  memset(rcp_conf, 0, sizeof(coap_oscore_rcp_conf_t));
  rcp_conf->recipient_id = coap_new_bin_const(recipient_id->s, recipient_id->length);
  if (rcp_conf->recipient_id == NULL)
    goto error;
  /* rcp_conf is released in oscore_add_recipient() */
  if (oscore_add_recipient(osc_ctx, rcp_conf, 0) == NULL)
    goto error;

  oscore_log_context(osc_ctx, "New Common context");
  oscore_enter_context(c_context, osc_ctx);

  return osc_ctx;

error:
  oscore_free_context(osc_ctx);
  return NULL;
}

oscore_ctx_t *
oscore_derive_ctx(coap_context_t *c_context, coap_oscore_conf_t *oscore_conf) {
  oscore_ctx_t *osc_ctx = NULL;
  oscore_sender_ctx_t *sender_ctx = NULL;
  coap_oscore_rcp_conf_t *rcp_conf;
  int ok;

  osc_ctx = coap_malloc_type(COAP_OSCORE_COM, sizeof(oscore_ctx_t));
  if (osc_ctx == NULL)
    goto error;
  memset(osc_ctx, 0, sizeof(oscore_ctx_t));

  sender_ctx = coap_malloc_type(COAP_OSCORE_SEN, sizeof(oscore_sender_ctx_t));
  if (sender_ctx == NULL)
    goto error;
  memset(sender_ctx, 0, sizeof(oscore_sender_ctx_t));

  osc_ctx->sender_context = sender_ctx;
  OSC_MOVE_PTR(osc_ctx->master_secret, oscore_conf->master_secret);
  OSC_MOVE_PTR(osc_ctx->master_salt, oscore_conf->master_salt);
  osc_ctx->aead_alg = oscore_conf->aead_alg;
  osc_ctx->hkdf_alg = oscore_conf->hkdf_alg;
  OSC_MOVE_PTR(osc_ctx->id_context, oscore_conf->id_context);
  osc_ctx->ssn_freq = oscore_conf->ssn_freq ? oscore_conf->ssn_freq : 1;
  osc_ctx->replay_window_size = oscore_conf->replay_window ?
                                oscore_conf->replay_window :
                                COAP_OSCORE_DEFAULT_REPLAY_WINDOW;
  osc_ctx->rfc8613_b_1_2 = oscore_conf->rfc8613_b_1_2;
  osc_ctx->rfc8613_b_2 = oscore_conf->rfc8613_b_2;
  osc_ctx->save_seq_num_func = oscore_conf->save_seq_num_func;
  osc_ctx->save_seq_num_func_param = oscore_conf->save_seq_num_func_param;

  if (osc_ctx->master_secret) {
    /* sender_ key */
    if (oscore_conf->break_sender_key)
      /* Interop testing */
      sender_ctx->sender_key = oscore_build_key(osc_ctx,
                                                osc_ctx->master_salt,
                                                osc_ctx->master_secret,
                                                osc_ctx->aead_alg,
                                                oscore_conf->sender->sender_id,
                                                coap_make_str_const("BAD"),
                                                cose_key_len(osc_ctx->aead_alg));
    else
      sender_ctx->sender_key = oscore_build_key(osc_ctx,
                                                osc_ctx->master_salt,
                                                osc_ctx->master_secret,
                                                osc_ctx->aead_alg,
                                                oscore_conf->sender->sender_id,
                                                coap_make_str_const("Key"),
                                                cose_key_len(osc_ctx->aead_alg));
    if (!sender_ctx->sender_key)
      goto error;

    /* common IV */
    osc_ctx->common_iv = oscore_build_key(osc_ctx,
                                          osc_ctx->master_salt,
                                          osc_ctx->master_secret,
                                          osc_ctx->aead_alg,
                                          NULL,
                                          coap_make_str_const("IV"),
                                          cose_nonce_len(osc_ctx->aead_alg));
    if (!osc_ctx->common_iv)
      goto error;

#if COAP_OSCORE_GROUP_SUPPORT
    if (oscore_conf->sender->group_mode || oscore_conf->sender->pairwise_mode) {
      size_t counter_signature_parameters_len = 0;
      uint8_t *counter_signature_parameters =
          oscore_cs_key_params(oscore_conf->sign_curve,
                               COSE_KTY_OKP,
                               &counter_signature_parameters_len);
      osc_ctx->group_enc_alg = oscore_conf->group_enc_alg;
      osc_ctx->sign_alg = oscore_conf->sign_alg;
      osc_ctx->pw_key_agree_alg = oscore_conf->pw_key_agree_alg;
      osc_ctx->sign_params = coap_new_bin_const(counter_signature_parameters,
                                                counter_signature_parameters_len);
      if (oscore_conf->sender->group_mode && coap_get_log_level() >= COAP_LOG_OSCORE) {
        oscore_log_hex_value(COAP_LOG_OSCORE, "Sign Params", osc_ctx->sign_params);
      }
      coap_free_type(COAP_STRING, counter_signature_parameters);
      /* signature Encryption Key */
      osc_ctx->sign_enc_key =
          oscore_build_key(osc_ctx,
                           osc_ctx->master_salt,
                           osc_ctx->master_secret,
                           osc_ctx->group_enc_alg,
                           NULL,
                           coap_make_str_const("SEKey"),
                           cose_key_len(osc_ctx->group_enc_alg));
      if (!osc_ctx->sign_enc_key)
        goto error;
    }
#endif /* COAP_OSCORE_GROUP_SUPPORT */
  }

  /*
   * Need to set the last Sender Seq Num based on ssn_freq
   * The value should only change if there is a change to ssn_freq
   * and (potentially) be lower than seq, then save_seq_num_func() is
   * immediately called on next SSN update.
   */
  sender_ctx->next_seq = oscore_conf->start_seq_num -
                         (oscore_conf->start_seq_num % (oscore_conf->ssn_freq > 0 ? oscore_conf->ssn_freq : 1));

  sender_ctx->seq = oscore_conf->start_seq_num;
  if (oscore_conf->sender) {
    OSC_MOVE_PTR(sender_ctx->sender_id, oscore_conf->sender->sender_id);
#if COAP_OSCORE_GROUP_SUPPORT
    sender_ctx->group_mode = oscore_conf->sender->group_mode;
    sender_ctx->pairwise_mode = oscore_conf->sender->pairwise_mode;
    OSC_MOVE_PTR(sender_ctx->g_public_key, oscore_conf->sender->gs_public_key);
    OSC_MOVE_PTR(sender_ctx->g_private_key, oscore_conf->sender->gs_private_key);
    if (sender_ctx->group_mode && coap_get_log_level() >= COAP_LOG_OSCORE) {
      char buffer[30];

      oscore_log_hex_value(COAP_LOG_OSCORE,
                           "Sender Priv DER",
                           sender_ctx->g_private_key->pri_der);
      oscore_log_int_value(COAP_LOG_OSCORE,
                           "  Sig Wire Size",
                           sender_ctx->g_private_key->wire_sign_size);
      oscore_log_hex_value(COAP_LOG_OSCORE,
                           "Sender Pub DER",
                           sender_ctx->g_public_key->pub_der);
      oscore_log_int_value(COAP_LOG_OSCORE,
                           "  Sig Wire Size",
                           sender_ctx->g_public_key->wire_sign_size);
      oscore_log_char_value(COAP_LOG_OSCORE,
                            "  Sig Cose Curve",
                            cose_get_curve_name(sender_ctx->g_public_key->sign_curve,
                                                buffer, sizeof(buffer)));
      oscore_log_char_value(COAP_LOG_OSCORE,
                            "  Sig Cose Hash",
                            cose_get_alg_name(sender_ctx->g_public_key->sign_hash,
                                              buffer, sizeof(buffer)));
    }
#endif /* COAP_OSCORE_GROUP_SUPPORT */
    coap_free_type(COAP_STRING, oscore_conf->sender);
    oscore_conf->sender = NULL;
  }

  rcp_conf = oscore_conf->recipient_chain;
  ok = 1;
  while (rcp_conf) {
    coap_oscore_rcp_conf_t *rcp_next = rcp_conf->next_recipient;

    /* rcp_conf is released in oscore_add_recipient() */
    if (oscore_add_recipient(osc_ctx, rcp_conf,
                             oscore_conf->break_recipient_key) == NULL) {
      coap_log_warn("OSCORE: Failed to add Client ID\n");
      ok = 0;
    }
    rcp_conf = rcp_next;
  }
  oscore_conf->recipient_chain = NULL;
  if (!ok)
    goto error;

  oscore_log_context(osc_ctx, "Common context");

  oscore_enter_context(c_context, osc_ctx);

  return osc_ctx;

error:
  oscore_free_context(osc_ctx);
  return NULL;
}

oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *osc_ctx, coap_oscore_rcp_conf_t *rcp_conf,
                     uint32_t break_key) {
  oscore_recipient_ctx_t *rcp_chain = osc_ctx->recipient_chain;
  oscore_recipient_ctx_t *rcp_ctx = NULL;

  if (rcp_conf->recipient_id->length > 7) {
    coap_log_warn("oscore_add_recipient: Maximum size of recipient_id is 7 bytes\n");
    goto free_rcp_conf;
  }
  /* Check this is not a duplicate recipient id */
  while (rcp_chain) {
    if (rcp_chain->recipient_id->length == rcp_conf->recipient_id->length &&
        memcmp(rcp_chain->recipient_id->s, rcp_conf->recipient_id->s,
               rcp_conf->recipient_id->length) == 0) {
      goto free_rcp_conf;
    }
    rcp_chain = rcp_chain->next_recipient;
  }
  rcp_ctx = (oscore_recipient_ctx_t *)coap_malloc_type(COAP_OSCORE_REC,
                                                       sizeof(oscore_recipient_ctx_t));
  if (rcp_ctx == NULL) {
    goto free_rcp_conf;
  }
  memset(rcp_ctx, 0, sizeof(oscore_recipient_ctx_t));

  if (osc_ctx->master_secret) {
    if (break_key)
      /* Interop testing */
      rcp_ctx->recipient_key = oscore_build_key(osc_ctx,
                                                osc_ctx->master_salt,
                                                osc_ctx->master_secret,
                                                osc_ctx->aead_alg,
                                                rcp_conf->recipient_id,
                                                coap_make_str_const("BAD"),
                                                cose_key_len(osc_ctx->aead_alg));
    else
      rcp_ctx->recipient_key = oscore_build_key(osc_ctx,
                                                osc_ctx->master_salt,
                                                osc_ctx->master_secret,
                                                osc_ctx->aead_alg,
                                                rcp_conf->recipient_id,
                                                coap_make_str_const("Key"),
                                                cose_key_len(osc_ctx->aead_alg));
    if (!rcp_ctx->recipient_key) {
      goto free_rcp_conf;
    }
  }
#if COAP_OSCORE_GROUP_SUPPORT
  if (osc_ctx->sender_context->group_mode) {
    if (osc_ctx->sender_context->pairwise_mode) {
      if (rcp_conf->group_mode) {
        rcp_ctx->mode = OSCORE_MODE_GROUP;
      } else {
        rcp_ctx->mode = OSCORE_MODE_PAIRWISE;
      }
    } else {
      rcp_ctx->mode = OSCORE_MODE_GROUP;
    }
  } else if (osc_ctx->sender_context->pairwise_mode) {
    if (rcp_conf->pairwise_mode) {
      rcp_ctx->mode = OSCORE_MODE_PAIRWISE;
    } else {
      rcp_ctx->mode = OSCORE_MODE_SINGLE;
    }
  } else {
    rcp_ctx->mode = OSCORE_MODE_SINGLE;
  }

  OSC_MOVE_PTR(rcp_ctx->recipient_id, rcp_conf->recipient_id);
  OSC_MOVE_PTR(rcp_ctx->g_public_key, rcp_conf->gr_public_key);

  if (rcp_ctx->mode == OSCORE_MODE_GROUP &&
      !coap_oscore_group_is_supported()) {
    coap_log_warn("OSCORE Group not supported by underlying TLS library\n");
    goto free_rcp_conf;
  }
  if (rcp_ctx->mode == OSCORE_MODE_PAIRWISE &&
      !coap_oscore_pairwise_is_supported()) {
    coap_log_warn("OSCORE Pairwise not supported by underlying TLS library\n");
    goto free_rcp_conf;
  }

  if (rcp_ctx->mode == OSCORE_MODE_GROUP &&
      coap_get_log_level() >= COAP_LOG_OSCORE) {
    char buffer[30];

    if (rcp_ctx->g_public_key != NULL)
      oscore_log_hex_value(COAP_LOG_OSCORE,
                           "Rcpt Pub DER",
                           rcp_ctx->g_public_key->pub_der);
    oscore_log_int_value(COAP_LOG_OSCORE,
                         "  Sig Wire Size",
                         rcp_ctx->g_public_key->wire_sign_size);
    oscore_log_char_value(COAP_LOG_OSCORE,
                          "  Sig Cose Curve",
                          cose_get_curve_name(rcp_ctx->g_public_key->sign_curve,
                                              buffer, sizeof(buffer)));
    oscore_log_char_value(COAP_LOG_OSCORE,
                          "  Sig Cose Hash",
                          cose_get_alg_name(rcp_ctx->g_public_key->sign_hash,
                                            buffer, sizeof(buffer)));
  }
  if (rcp_ctx->mode == OSCORE_MODE_PAIRWISE) {
    oscore_sender_ctx_t *snd_ctx = osc_ctx->sender_context;
    coap_bin_const_t *shared_secret = NULL;
    coap_binary_t *ikm = NULL;
    if (coap_crypto_derive_shared_secret(osc_ctx->pw_key_agree_alg,
                                         snd_ctx->g_private_key->pri_raw,
                                         rcp_ctx->g_public_key->pub_raw,
                                         &shared_secret)) {
      ikm = coap_new_binary(snd_ctx->g_public_key->pub_der->length +
                            rcp_ctx->g_public_key->pub_der->length +
                            shared_secret->length);
      if (!ikm)
        goto fail;

      /* Do the Pairwise Sender Key */
      coap_delete_bin_const(rcp_ctx->pw_sender_key);
      memcpy(&ikm->s[0], snd_ctx->g_public_key->pub_der->s,
             snd_ctx->g_public_key->pub_der->length);
      memcpy(&ikm->s[snd_ctx->g_public_key->pub_der->length],
             rcp_ctx->g_public_key->pub_der->s,
             rcp_ctx->g_public_key->pub_der->length);
      memcpy(&ikm->s[snd_ctx->g_public_key->pub_der->length +
                                                            rcp_ctx->g_public_key->pub_der->length],
             shared_secret->s,
             shared_secret->length);
      rcp_ctx->pw_sender_key =
          oscore_build_key(osc_ctx,
                           snd_ctx->sender_key,
                           (coap_bin_const_t *)ikm,
                           osc_ctx->aead_alg,
                           rcp_ctx->recipient_id,
                           coap_make_str_const("Key"),
                           cose_key_len(osc_ctx->aead_alg));
      if (!rcp_ctx->pw_sender_key)
        goto fail;
      /* Do the Pairwise Recipient Key */
      coap_delete_bin_const(rcp_ctx->pw_recipient_key);
      memcpy(&ikm->s[0], rcp_ctx->g_public_key->pub_der->s,
             rcp_ctx->g_public_key->pub_der->length);
      memcpy(&ikm->s[rcp_ctx->g_public_key->pub_der->length],
             snd_ctx->g_public_key->pub_der->s,
             snd_ctx->g_public_key->pub_der->length);
      memcpy(&ikm->s[rcp_ctx->g_public_key->pub_der->length +
                                                            snd_ctx->g_public_key->pub_der->length],
             shared_secret->s,
             shared_secret->length);
      rcp_ctx->pw_recipient_key =
          oscore_build_key(osc_ctx,
                           rcp_ctx->recipient_key,
                           (coap_bin_const_t *)ikm,
                           osc_ctx->aead_alg,
                           snd_ctx->sender_id,
                           coap_make_str_const("Key"),
                           cose_key_len(osc_ctx->aead_alg));
      coap_delete_binary(ikm);
      coap_delete_bin_const(shared_secret);
    } else {
fail:
      coap_delete_binary(ikm);
      coap_delete_bin_const(shared_secret);
      oscore_free_recipient(rcp_ctx);
      coap_free_type(COAP_STRING, rcp_conf);
      return NULL;
    }
  }
#else /* ! COAP_OSCORE_GROUP_SUPPORT */
  rcp_ctx->mode = OSCORE_MODE_SINGLE;
  OSC_MOVE_PTR(rcp_ctx->recipient_id, rcp_conf->recipient_id);
#endif /* ! COAP_OSCORE_GROUP_SUPPORT */

  rcp_ctx->initial_state = 1;
  rcp_ctx->osc_ctx = osc_ctx;

  rcp_chain = osc_ctx->recipient_chain;
  rcp_ctx->next_recipient = rcp_chain;
  osc_ctx->recipient_chain = rcp_ctx;
  /* Just free rcp_conf as all configured values are now in rcp_ctx */
  coap_free_type(COAP_STRING, rcp_conf);
  return rcp_ctx;

free_rcp_conf:
  coap_free_type(COAP_OSCORE_REC, rcp_ctx);
  coap_delete_oscore_rcp_conf(rcp_conf);
  return NULL;
}

int
oscore_delete_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid) {
  oscore_recipient_ctx_t *prev = NULL;
  oscore_recipient_ctx_t *next = osc_ctx->recipient_chain;
  while (next) {
    if (next->recipient_id->length == rid->length &&
        memcmp(next->recipient_id->s, rid->s, rid->length) == 0) {
      if (prev != NULL)
        prev->next_recipient = next->next_recipient;
      else
        osc_ctx->recipient_chain = next->next_recipient;
      oscore_free_recipient(next);
      return 1;
    }
    prev = next;
    next = next->next_recipient;
  }
  return 0;
}

void
oscore_free_association(oscore_association_t *association) {
  if (association) {
    coap_delete_pdu(association->sent_pdu);
    coap_delete_bin_const(association->token);
    coap_delete_bin_const(association->aad);
    coap_delete_bin_const(association->nonce);
    coap_delete_bin_const(association->partial_iv);
    coap_free_type(COAP_STRING, association);
  }
}

int
oscore_new_association(coap_session_t *session,
                       coap_pdu_t *sent_pdu,
                       coap_bin_const_t *token,
                       oscore_recipient_ctx_t *recipient_ctx,
                       coap_bin_const_t *aad,
                       coap_bin_const_t *nonce,
                       coap_bin_const_t *partial_iv,
                       int is_observe) {
  oscore_association_t *association;

  association = coap_malloc_type(COAP_STRING, sizeof(oscore_association_t));
  if (association == NULL)
    return 0;

  memset(association, 0, sizeof(oscore_association_t));
  association->recipient_ctx = recipient_ctx;
  association->is_observe = is_observe;

  if (sent_pdu) {
    size_t size;
    const uint8_t *data;

    association->sent_pdu = coap_pdu_duplicate(sent_pdu, session,
                                               token->length, token->s, NULL);
    if (association->sent_pdu == NULL)
      goto error;
    if (coap_get_data(sent_pdu, &size, &data)) {
      coap_add_data(association->sent_pdu, size, data);
    }
  }
  association->token = coap_new_bin_const(token->s, token->length);
  if (association->token == NULL)
    goto error;

  if (aad) {
    association->aad = coap_new_bin_const(aad->s, aad->length);
    if (association->aad == NULL)
      goto error;
  }

  if (nonce) {
    association->nonce = coap_new_bin_const(nonce->s, nonce->length);
    if (association->nonce == NULL)
      goto error;
  }

  if (partial_iv) {
    association->partial_iv =
        coap_new_bin_const(partial_iv->s, partial_iv->length);
    if (association->partial_iv == NULL)
      goto error;
  }

  OSCORE_ASSOCIATIONS_ADD(session->associations, association);
  return 1;

error:
  oscore_free_association(association);
  return 0;
}

oscore_association_t *
oscore_find_association(coap_session_t *session, coap_bin_const_t *token) {
  oscore_association_t *association;

  OSCORE_ASSOCIATIONS_FIND(session->associations, token, association);
  return association;
}

int
oscore_delete_association(coap_session_t *session,
                          oscore_association_t *association) {
  if (association) {
    OSCORE_ASSOCIATIONS_DELETE(session->associations, association);
    oscore_free_association(association);
    return 1;
  }
  return 0;
}

void
oscore_delete_server_associations(coap_session_t *session) {
  if (session) {
    oscore_association_t *association;
    oscore_association_t *tmp;

    OSCORE_ASSOCIATIONS_ITER_SAFE(session->associations, association, tmp) {
      OSCORE_ASSOCIATIONS_DELETE(session->associations, association);
      oscore_free_association(association);
    }
    session->associations = NULL;
  }
}
