//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

#include "netcrypto.h"
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
//#define PALAPI __stdcall

int
PALAPI
GetX509Thumbprint(
    X509* x509,
    unsigned char* pBuf,
    int cBuf)
{
    if (!x509)
    {
        return 0;
    }

    if (cBuf < SHA_DIGEST_LENGTH)
    {
        return -SHA_DIGEST_LENGTH;
    }

    memcpy(pBuf, x509->sha1_hash, SHA_DIGEST_LENGTH);
    return 1;
}

ASN1_INTEGER*
PALAPI
GetX509NotBefore(
    X509* x509)
{
    if (x509 && x509->cert_info && x509->cert_info->validity)
    {
        return x509->cert_info->validity->notBefore;
    }

    return NULL;
}

ASN1_INTEGER*
PALAPI
GetX509NotAfter(
    X509* x509)
{
    if (x509 && x509->cert_info && x509->cert_info->validity)
    {
        return x509->cert_info->validity->notAfter;
    }

    return NULL;
}

int
PALAPI
GetX509Version(
    X509* x509)
{
    if (x509 && x509->cert_info)
    {
        long ver = ASN1_INTEGER_get(x509->cert_info->version);
        return (int)ver;
    }

    return -1;
}

const char*
PALAPI
GetX509PublicKeyAlgorithm(
    X509* x509)
{
    if (x509 && x509->cert_info && x509->cert_info->key && x509->cert_info->key->algor)
    {
        return OBJ_nid2ln(OBJ_obj2nid(x509->cert_info->key->algor->algorithm));
    }

    return NULL;
}

ASN1_BIT_STRING*
PALAPI
GetX509PublicKeyBytes(
    X509* x509)
{
    if (x509 && x509->cert_info && x509->cert_info->key)
    {
        return x509->cert_info->key->public_key;
    }

    return NULL;
}

RSA*
PALAPI
GetEvpPkeyRsa(
    EVP_PKEY* pkey)
{
    if (pkey)
    {
        return pkey->pkey.rsa;
    }

    return NULL;
}
