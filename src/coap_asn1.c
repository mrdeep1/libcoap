/* coap_asn1.c -- ASN.1 handling functions
*
* Copyright (C) 2020-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
*
 * SPDX-License-Identifier: BSD-2-Clause
 *
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

/**
 * @file coap_asn1.c
 * @brief CoAP specific ASN.1 handling
 */

#include "coap3/coap_internal.h"

size_t
asn1_len(const uint8_t **ptr) {
  size_t len = 0;

  if ((**ptr) & 0x80) {
    size_t octets = (**ptr) & 0x7f;
    (*ptr)++;
    while (octets) {
      len = (len << 8) + (**ptr);
      (*ptr)++;
      octets--;
    }
  } else {
    len = (**ptr) & 0x7f;
    (*ptr)++;
  }
  return len;
}

coap_asn1_tag_t
asn1_tag_c(const uint8_t **ptr, int *constructed, int *cls) {
  coap_asn1_tag_t tag = 0;
  uint8_t byte;

  byte = (**ptr);
  *constructed = (byte & 0x20) ? 1 : 0;
  *cls = byte >> 6;
  tag = byte & 0x1F;
  (*ptr)++;
  if (tag < 0x1F)
    return tag;

  /* Tag can be one byte or more based on B8 */
  byte = (**ptr);
  while (byte & 0x80) {
    tag = (tag << 7) + (byte & 0x7F);
    (*ptr)++;
    byte = (**ptr);
  }
  /* Do the final one */
  tag = (tag << 7) + (byte & 0x7F);
  (*ptr)++;
  return tag;
}

/* caller must free off returned coap_binary_t* */
coap_binary_t *
get_asn1_tag(coap_asn1_tag_t ltag, const uint8_t *ptr, size_t tlen,
             asn1_validate validate) {
  int constructed;
  int class;
  const uint8_t *acp = ptr;
  uint8_t tag = asn1_tag_c(&acp, &constructed, &class);
  size_t len = asn1_len(&acp);
  coap_binary_t *tag_data;

  while (tlen > 0 && len <= tlen) {
    if (class == 2 && constructed == 1) {
      /* Skip over element description */
      tag = asn1_tag_c(&acp, &constructed, &class);
      len = asn1_len(&acp);
    }
    if (tag == ltag) {
      if (!validate || validate(acp, len)) {
        tag_data = coap_new_binary(len);
        if (tag_data == NULL)
          return NULL;
        tag_data->length = len;
        memcpy(tag_data->s, acp, len);
        return tag_data;
      }
    }
    if (tag == 0x10 && constructed == 1) {
      /* SEQUENCE or SEQUENCE OF */
      tag_data = get_asn1_tag(ltag, acp, len, validate);
      if (tag_data)
        return tag_data;
    }
    acp += len;
    tlen -= len;
    tag = asn1_tag_c(&acp, &constructed, &class);
    len = asn1_len(&acp);
  }
  return NULL;
}

/* first part of Raw public key, this is the start of the Subject Public Key */
static const unsigned char cert_asn1_header1[] = {
  0x30, 0x59, /* SEQUENCE, length 89 bytes */
  0x30, 0x13, /* SEQUENCE, length 19 bytes */
  0x06, 0x07, /* OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1) */
  0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
};
/* PrimeX will get inserted */
#if 0
0x06, 0x08, /* OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7) */
      0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
#endif
static const unsigned char cert_asn1_header2[] = {
  0x03, 0x42, /* BIT STRING, length 66 bytes */
  /* Note: 0 bits (0x00) and no compression (0x04) are already in the certificate */
};

coap_binary_t *
get_asn1_spki(const uint8_t *data, size_t size) {
  coap_binary_t *pub_key = get_asn1_tag(COAP_ASN1_BITSTRING, data, size, NULL);
  coap_binary_t *prime = get_asn1_tag(COAP_ASN1_IDENTIFIER, data, size, NULL);
  coap_binary_t *spki = NULL;

  if (pub_key && prime) {
    size_t header_size = sizeof(cert_asn1_header1) +
                         2 +
                         prime->length +
                         sizeof(cert_asn1_header2);
    spki = coap_new_binary(header_size + pub_key->length);
    if (spki) {
      memcpy(&spki->s[header_size], pub_key->s, pub_key->length);
      memcpy(spki->s, cert_asn1_header1, sizeof(cert_asn1_header1));
      spki->s[sizeof(cert_asn1_header1)] = COAP_ASN1_IDENTIFIER;
      spki->s[sizeof(cert_asn1_header1)+1] = (uint8_t)prime->length;
      memcpy(&spki->s[sizeof(cert_asn1_header1)+2],
             prime->s, prime->length);
      memcpy(&spki->s[sizeof(cert_asn1_header1)+2+prime->length],
             cert_asn1_header2, sizeof(cert_asn1_header2));
      spki->length = header_size + pub_key->length;
    }
  }
  if (pub_key)
    coap_delete_binary(pub_key);
  if (prime)
    coap_delete_binary(prime);
  return spki;
}

coap_binary_t *
coap_asn1_split_r_s(coap_binary_t *asn1, size_t size) {
  int constructed;
  int class;
  const uint8_t *acp = asn1->s;
  uint8_t tag;
  size_t len;
  coap_binary_t *sign;

  if (asn1->s[0] != 0x30)
    return NULL;

  tag = asn1_tag_c(&acp, &constructed, &class);
  len = asn1_len(&acp);

  tag = asn1_tag_c(&acp, &constructed, &class);
  len = asn1_len(&acp);
  if (tag != COAP_ASN1_INTEGER)
    return NULL;
  sign = coap_new_binary(size);
  if (sign == NULL)
    return NULL;
  if (len < size/2) {
    /* pad with leading 0s */
    memset(&sign->s[0], 0, size/2 - len);
    memcpy(&sign->s[size/2 - len], acp, len);
  } else {
    /* drop leading 0s if needed */
    memcpy(&sign->s[0], acp + len - size/2, len);
  }

  acp += len;
  tag = asn1_tag_c(&acp, &constructed, &class);
  len = asn1_len(&acp);
  if (tag != COAP_ASN1_INTEGER) {
    coap_delete_binary(sign);
    return NULL;
  }
  if (len < size/2) {
    /* pad with leading 0s */
    memset(&sign->s[size/2], 0, size/2 - len);
    memcpy(&sign->s[size/2 + size/2 - len], acp, len);
  } else {
    /* drop leading 0s if needed */
    memcpy(&sign->s[size/2], acp + len - size/2, len);
  }
  return sign;
}

static void
asn1_add_integer(u_char **cp, u_char *integer, size_t int_len) {
  size_t i;

  *((*cp)++) = COAP_ASN1_INTEGER;
  if (integer[0] & 0x80) {
    *((*cp)++) = int_len + 1;
    *((*cp)++) = 0x00;
    i = 0;
  } else {
    /* drop leading 0s if needed */
    for (i = 0; i < int_len - 1; i++) {
      if (integer[i] != 0)
        break;
    }
    *((*cp)++) = int_len - i;
  }
  memcpy(*cp, &integer[i], int_len - i);
  *cp += int_len - i;
}

coap_binary_t *
coap_asn1_r_s_join(coap_binary_t *r_s) {
  coap_binary_t *sign = coap_new_binary(r_s->length + 8);
  u_char *cp;

  if (sign == NULL)
    return NULL;

  cp = sign->s;
  *(cp++) = 0x30; /* SEQUENCE */
  *(cp++) = 0x00; /* Length - to be filled in later */

  asn1_add_integer(&cp, r_s->s, r_s->length/2);

  asn1_add_integer(&cp, &r_s->s[r_s->length/2], r_s->length/2);

  sign->s[1] = cp - sign->s - 2;
  sign->length = cp - sign->s;
  return sign;
}

#if COAP_OSCORE_GROUP_SUPPORT
static void
asn1_add_seq_bin_oid(u_char **cp, const u_char *oid, size_t oid_len) {
  u_char *keep_cp = *cp;

  *((*cp)++) = 0x30; /* SEQUENCE */
  *((*cp)++) = 0x00; /* Length - to be filled in later */

  *((*cp)++) = COAP_ASN1_IDENTIFIER;
  *((*cp)++) = oid_len;
  memcpy(*cp, oid, oid_len);
  *cp += oid_len;
  keep_cp[1] = *cp - keep_cp - 2;
}

static void
asn1_add_octet_string(u_char **cp, const u_char *octet, size_t octet_len) {
  *((*cp)++) = COAP_ASN1_OCTETSTRING;
  *((*cp)++) = octet_len;
  memcpy(*cp, octet, octet_len);
  *cp += octet_len;
}


coap_binary_t *
coap_asn1_pri_key(cose_curve_t curve, coap_bin_const_t *raw) {
  coap_bin_const_t *oid = cose_get_curve_bin_oid(curve);
  coap_binary_t *pri_der;
  u_char *cp;
  u_char val0 = 0;

  if (oid == NULL)
    return NULL;

  pri_der = coap_new_binary(13 + oid->length + raw->length);
  if (pri_der == NULL)
    return NULL;

  cp = pri_der->s;
  *(cp++) = 0x30; /* SEQUENCE */
  *(cp++) = 0x00; /* Length - to be filled in later */

  asn1_add_integer(&cp, &val0, 1);

  asn1_add_seq_bin_oid(&cp, oid->s, oid->length);
  *(cp++) = COAP_ASN1_OCTETSTRING;
  *(cp++) = raw->length + 2;
  asn1_add_octet_string(&cp, raw->s, raw->length);

  pri_der->s[1] = cp - pri_der->s - 2;
  assert(pri_der->length >= (size_t)(cp - pri_der->s));
  pri_der->length = cp - pri_der->s;
  return pri_der;
}
#endif /* COAP_OSCORE_GROUP_SUPPORT */
