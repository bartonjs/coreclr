//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define NAME_TYPE_SIMPLE 0
#define NAME_TYPE_EMAIL 1
#define NAME_TYPE_UPN 2
#define NAME_TYPE_DNS 3
#define NAME_TYPE_DNSALT 4
#define NAME_TYPE_URL 5

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

    return NULL;
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
GetX509EkuFieldCount(
    EXTENDED_KEY_USAGE* eku)
{
    return sk_ASN1_OBJECT_num(eku);
}

ASN1_OBJECT*
GetX509EkuField(
    EXTENDED_KEY_USAGE* eku,
    int loc)
{
    return sk_ASN1_OBJECT_value(eku, loc);
}

BIO*
GetX509NameInfo(
    X509* x509,
    int nameType,
    int forIssuer)
{
    static const char szOidUpn[] = "1.3.6.1.4.1.311.20.2.3";

    if (!x509 || !x509->cert_info || nameType < NAME_TYPE_SIMPLE || nameType > NAME_TYPE_URL)
    {
        return NULL;
    }

    if (nameType == NAME_TYPE_SIMPLE)
    {
        X509_NAME* name = forIssuer ? x509->cert_info->issuer : x509->cert_info->subject;

        if (name)
        {
            ASN1_STRING* cn = NULL;
            ASN1_STRING* ou = NULL;
            ASN1_STRING* o = NULL;
            ASN1_STRING* e = NULL;
            ASN1_STRING* firstRdn = NULL;

            // Walk the list backwards because it is stored in stack order
            for (int i = X509_NAME_entry_count(name) - 1; i >= 0; --i)
            {
                X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);

                if (!entry)
                {
                    continue;
                }

                ASN1_OBJECT* oid = X509_NAME_ENTRY_get_object(entry);
                ASN1_STRING* str = X509_NAME_ENTRY_get_data(entry);

                if (!oid || !str)
                {
                    continue;
                }

                int nid = OBJ_obj2nid(oid);

                if (nid == NID_commonName)
                {
                    // CN wins, so no need to keep looking.
                    cn = str;
                    break;
                }
                else if (nid == NID_organizationalUnitName)
                {
                    ou = str;
                }
                else if (nid == NID_organizationName)
                {
                    o = str;
                }
                else if (nid == NID_pkcs9_emailAddress)
                {
                    e = str;
                }
                else if (!firstRdn)
                {
                    firstRdn = str;
                }
            }

            ASN1_STRING* answer = cn;

            // If there was no CN, but there was something, then perform fallbacks.
            if (!answer && firstRdn)
            {
                answer = ou;

                if (!answer)
                {
                    answer = o;
                }

                if (!answer)
                {
                    answer = e;
                }

                if (!answer)
                {
                    answer = firstRdn;
                }
            }

            if (answer)
            {
                BIO* b = BIO_new(BIO_s_mem());
                ASN1_STRING_print_ex(b, answer, 0);
                return b;
            }
        }
    }

    if (nameType == NAME_TYPE_SIMPLE ||
        nameType == NAME_TYPE_DNS ||
        nameType == NAME_TYPE_DNSALT ||
        nameType == NAME_TYPE_EMAIL ||
        nameType == NAME_TYPE_UPN ||
        nameType == NAME_TYPE_URL)
    {
        int expectedType = -1;

        switch (nameType)
        {
            case NAME_TYPE_DNS:
            case NAME_TYPE_DNSALT:
                expectedType = GEN_DNS;
                break;
            case NAME_TYPE_SIMPLE:
            case NAME_TYPE_EMAIL:
                expectedType = GEN_EMAIL;
                break;
            case NAME_TYPE_UPN:
                expectedType = GEN_OTHERNAME;
                break;
            case NAME_TYPE_URL:
                expectedType = GEN_URI;
                break;
        }

        STACK_OF(GENERAL_NAME)* altNames =
            X509_get_ext_d2i(x509, forIssuer ? NID_issuer_alt_name : NID_subject_alt_name, NULL, NULL);

        if (altNames)
        {
            int i;

            for (i = 0; i < sk_GENERAL_NAME_num(altNames); ++i)
            {
                GENERAL_NAME* altName = sk_GENERAL_NAME_value(altNames, i);

                if (altName && altName->type == expectedType)
                {
                    ASN1_STRING* str = NULL;

                    switch (nameType)
                    {
                        case NAME_TYPE_SIMPLE:
                        case NAME_TYPE_DNS:
                        case NAME_TYPE_DNSALT:
                            str = altName->d.dNSName;
                            break;
                        case NAME_TYPE_EMAIL:
                            str = altName->d.rfc822Name;
                            break;
                        case NAME_TYPE_URL:
                            str = altName->d.uniformResourceIdentifier;
                            break;
                        case NAME_TYPE_UPN:
                        {
                            OTHERNAME* value = altName->d.otherName;

                            if (value)
                            {
                                // Enough more padding than szOidUpn that a \0 won't accidentally align
                                char localOid[sizeof(szOidUpn) + 3];
                                int cchLocalOid = 1 + OBJ_obj2txt(localOid, sizeof(localOid), value->type_id, 1);

                                if (sizeof(szOidUpn) == cchLocalOid &&
                                    0 == strncmp(localOid, szOidUpn, sizeof(szOidUpn)))
                                {
                                    //OTHERNAME->ASN1_TYPE->union.field
                                    str = value->value->value.asn1_string;
                                }
                            }

                            break;
                        }
                    }

                    if (str)
                    {
                        BIO* b = BIO_new(BIO_s_mem());
                        ASN1_STRING_print_ex(b, str, 0);
                        sk_GENERAL_NAME_free(altNames);
                        return b;
                    }
                }
            }

            sk_GENERAL_NAME_free(altNames);
        }
    }

    if (nameType == NAME_TYPE_EMAIL ||
        nameType == NAME_TYPE_DNS)
    {
        X509_NAME* name = forIssuer ? x509->cert_info->issuer : x509->cert_info->subject;
        int expectedNid = NID_undef;

        switch (nameType)
        {
            case NAME_TYPE_EMAIL:
                expectedNid = NID_pkcs9_emailAddress;
                break;
            case NAME_TYPE_DNS:
                expectedNid = NID_commonName;
                break;
        }

        if (name)
        {
            // Walk the list backwards because it is stored in stack order
            for (int i = X509_NAME_entry_count(name) - 1; i >= 0; --i)
            {
                X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);

                if (!entry)
                {
                    continue;
                }

                ASN1_OBJECT* oid = X509_NAME_ENTRY_get_object(entry);
                ASN1_STRING* str = X509_NAME_ENTRY_get_data(entry);

                if (!oid || !str)
                {
                    continue;
                }

                int nid = OBJ_obj2nid(oid);

                if (nid == expectedNid)
                {
                    BIO* b = BIO_new(BIO_s_mem());
                    ASN1_STRING_print_ex(b, str, 0);
                    return b;
                }
            }
        }
    }

    return NULL;
}
