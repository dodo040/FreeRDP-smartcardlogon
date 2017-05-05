/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP X509
 *
 * Copyright 2017 Dorian Ducournau <dorian.ducournau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef X509_H
#define X509_H

#include <freerdp/log.h>
#include <freerdp/crypto/crypto.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

/** Certificate Common Name */
#define CERT_CN	1
/** Certificate subject */
#define CERT_SUBJECT	2
/** Kerberos principal name */
#define CERT_KPN	3
/** Certificate e-mail */
#define CERT_EMAIL	4
/** Microsoft's Universal Principal Name */
#define CERT_UPN	5
/** Certificate issuer */
#define CERT_ISSUER	6
/** Certificate key algorithm */
#define CERT_KEY_ALG	7

/** Max size of returned certificate content array */
#define CERT_INFO_SIZE 16
/** Max number of entries to find from certificate */
#define CERT_INFO_MAX_ENTRIES ( CERT_INFO_SIZE - 1 )

#ifndef CERT_INFO_C
#define CERTINFO_EXTERN extern
#else
#define CERTINFO_EXTERN
#endif

struct cert_policy_st
{
	int ca_policy;
	int crl_policy;
	int signature_policy;
	const char* ca_dir;
	const char* crl_dir;
	int ocsp_policy;
};

typedef struct cert_policy_st cert_policy;

#include <openssl/x509.h>
typedef const char* ALGORITHM_TYPE;

char* clone_str(const char* str);
char* bin2hex(const unsigned char* binstr, const int len);
void add_cert(X509* cert, X509** *certs, int* ncerts);
char** cert_info(X509* x509, int type);


#if OPENSSL_VERSION_NUMBER >=  0x00907000L
#define UID_TYPE NID_x500UniqueIdentifier
#else
#define UID_TYPE NID_uniqueIdentifier
#endif

#endif
