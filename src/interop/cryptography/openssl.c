//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int
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
GetX509PublicKeyAlgorithm(
    X509* x509)
{
    if (x509 && x509->cert_info && x509->cert_info->key && x509->cert_info->key->algor)
    {
        return OBJ_nid2ln(OBJ_obj2nid(x509->cert_info->key->algor->algorithm));
    }

    return NULL;
}

const char*
GetX509SignatureAlgorithm(
    X509* x509)
{
    if (x509 && x509->sig_alg && x509->sig_alg->algorithm)
    {
        return OBJ_nid2ln(OBJ_obj2nid(x509->sig_alg->algorithm));
    }
}

ASN1_BIT_STRING*
GetX509PublicKeyBytes(
    X509* x509)
{
    if (x509 && x509->cert_info && x509->cert_info->key)
    {
        return x509->cert_info->key->public_key;
    }

    return NULL;
}

// Many ASN1 types are actually the same type in OpenSSL:
// STRING
// INTEGER
// ENUMERATED
// BIT_STRING
// OCTET_STRING
// PRINTABLESTRING
// T61STRING
// IA5STRING
// GENERALSTRING
// UNIVERSALSTRING
// BMPSTRING
// UTCTIME
// TIME
// GENERALIZEDTIME
// VISIBLEStRING
// UTF8STRING
//
// So this function will really work on all of them.
int
GetAsn1StringBytes(
    ASN1_STRING* asn1,
    unsigned char* pBuf,
    int cBuf)
{
    if (!asn1)
    {
        return 0;
    }

    if (!pBuf || cBuf < asn1->length)
    {
        return -asn1->length;
    }

    memcpy(pBuf, asn1->data, asn1->length);
    return 1;
}

int
GetX509NameRawBytes(
    X509_NAME* x509Name,
    unsigned char* pBuf,
    int cBuf)
{
    if (!x509Name || !x509Name->bytes)
    {
        return 0;
    }

    if (!pBuf || cBuf < x509Name->bytes->length)
    {
        return -x509Name->bytes->length;
    }

    memcpy(pBuf, x509Name->bytes->data, x509Name->bytes->length);
    return 1;
}

int
GetEkuFieldCount(
    EXTENDED_KEY_USAGE* eku)
{
    return sk_ASN1_OBJECT_num(eku);
}

ASN1_OBJECT*
GetEkuField(
    EXTENDED_KEY_USAGE* eku,
    int loc)
{
    return sk_ASN1_OBJECT_value(eku, loc);
}
