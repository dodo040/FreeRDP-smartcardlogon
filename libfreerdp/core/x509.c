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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "x509.h"

static char** cert_info_cn(X509* x509);
static char** cert_info_subject(X509* x509);
static char** cert_info_issuer(X509* x509);
static char** cert_info_kpn(X509* x509);
static char** cert_info_upn(X509* x509);
static char** cert_key_alg(X509* x509);

#define TAG FREERDP_TAG("core.x509")

/* returns a clone of provided string */
char* clone_str(const char* str)
{
	size_t len = strlen(str);
	char* dst = malloc(1 + len);

	if (!dst) return NULL;

	strncpy(dst, str, len);
	*(dst + len) = '\0';
	return dst;
}

/* print a binary array in xx:xx:.... format */
char* bin2hex(const unsigned char* binstr, const int len)
{
	int i;
	char* pt;
	char* res = malloc(1 + 3 * len);

	if (!res) return NULL;

	if (len == 0)
	{
		*res = 0;
		return res;
	}

	for (i = 0, pt = res; i < len; i++, pt += 3)
	{
		sprintf(pt, "%02X:", binstr[i]);
	}

	*(--pt) = '\0'; /* replace last ':' with '\0' */
	return res;
}

/**
* Generate and compose a certificate chain
*/
void add_cert(X509* cert, X509** *certs, int* ncerts)
{
	X509** certs2;

	/* sanity checks */
	if (!cert) return;

	if (!certs) return;

	if (!ncerts) return;

	/* no certs so far */
	if (!*certs)
	{
		*certs = malloc(sizeof(void*));

		if (!*certs) return;

		*certs[0] = cert;
		*ncerts = 1;
		return;
	}

	/* enlarge current cert chain by malloc(new)+copy()+free(old) */
	certs2 = malloc(sizeof(void*) * ((*ncerts) + 1));

	if (!certs2) return;

	memcpy(certs2, *certs, sizeof(void*) * (*ncerts));
	certs2[*ncerts] = cert;
	free(*certs);
	*certs = certs2;
	(*ncerts)++;
}

/*
* Extract Certificate's Common Name
*/
static char** cert_info_cn(X509* x509)
{
	static char* results[CERT_INFO_SIZE];
	int lastpos, position;
	X509_NAME* name = X509_get_subject_name(x509);

	if (!name)
	{
		WLog_ERR(TAG, "Certificate has no subject");
		return NULL;
	}

	for (position = 0; position < CERT_INFO_SIZE; position++) results[position] = NULL;

	position = 0;
	lastpos = X509_NAME_get_index_by_NID(name, NID_commonName, -1);

	if (lastpos == -1)
	{
		WLog_ERR(TAG, "Certificate has no UniqueID");
		return NULL;
	}

	while ((lastpos != -1) && (position < CERT_INFO_MAX_ENTRIES))
	{
		X509_NAME_ENTRY* entry;
		ASN1_STRING* str;
		unsigned char* txt;

		if (!(entry = X509_NAME_get_entry(name, lastpos)))
		{
			WLog_ERR(TAG, "X509_get_name_entry() failed: %s", ERR_error_string(ERR_get_error(), NULL));
			return results;
		}

		if (!(str = X509_NAME_ENTRY_get_data(entry)))
		{
			WLog_ERR(TAG, "X509_NAME_ENTRY_get_data() failed: %s", ERR_error_string(ERR_get_error(), NULL));
			return results;
		}

		if ((ASN1_STRING_to_UTF8(&txt, str)) < 0)
		{
			WLog_ERR(TAG, "ASN1_STRING_to_UTF8() failed: %s", ERR_error_string(ERR_get_error(), NULL));
			return results;
		}

		WLog_DBG(TAG, "%s = [%s]", OBJ_nid2sn(NID_commonName), txt);
		results[position++] = clone_str((const char*)txt);
		OPENSSL_free(txt);
		lastpos = X509_NAME_get_index_by_NID(name, NID_commonName, lastpos);
	}

	/* no more UID's available in certificate */
	return results;
}

/*
* Extract Certificate's Subject
*/
static char** cert_info_subject(X509* x509)
{
	X509_NAME* subject;
	static char* entries[2] = { NULL, NULL };
	entries[0] = malloc(256);

	if (!entries[0]) return NULL;

	subject = X509_get_subject_name(x509);

	if (!subject)
	{
		WLog_ERR(TAG, "X509_get_subject_name failed");
		return NULL;
	}

	X509_NAME_oneline(subject, entries[0], 256);
	return entries;
}

/*
* Extract Certificate's Issuer
*/
static char** cert_info_issuer(X509* x509)
{
	X509_NAME* issuer;
	static char* entries[2] = { NULL, NULL };
	entries[0] = malloc(256);

	if (!entries[0]) return NULL;

	issuer = X509_get_issuer_name(x509);

	if (!issuer)
	{
		WLog_ERR(TAG, "X509_get_issuer_name failed");
		return NULL;
	}

	X509_NAME_oneline(issuer, entries[0], 256);
	return entries;
}

/*
* Extract Certificate's Kerberos Principal Name
*/
static char** cert_info_kpn(X509* x509)
{
	int i, j;
	static char* entries[CERT_INFO_SIZE];
	STACK_OF(GENERAL_NAME) *gens;
	GENERAL_NAME* name;
	ASN1_OBJECT* krb5PrincipalName;
	WLog_DBG(TAG, "Trying to find a Kerberos Principal Name in certificate");
	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	krb5PrincipalName = OBJ_txt2obj("1.3.6.1.5.2.2", 1);

	if (!gens)
	{
		WLog_ERR(TAG, "No alternate name extensions");
		return NULL; /* no alternate names */
	}

	if (!krb5PrincipalName)
	{
		WLog_ERR(TAG, "Cannot map KPN object");
		return NULL;
	}

	for (j = 0; j < CERT_INFO_SIZE; j++) entries[j] = NULL;

	for (i = 0, j = 0; (i < sk_GENERAL_NAME_num(gens)) && (j < CERT_INFO_MAX_ENTRIES); i++)
	{
		name = sk_GENERAL_NAME_value(gens, i);

		if (name && name->type == GEN_OTHERNAME)    /* test for UPN */
		{
			WLog_ERR(TAG, "GEN_OTHERNAME");

			if (OBJ_cmp(name->d.otherName->type_id, krb5PrincipalName))
			{
				WLog_ERR(TAG, "krb5PrincipalName");
				continue; /* object is not a UPN */
			}
			else
			{
				/* NOTE:
				from PKINIT RFC, I deduce that stored format for kerberos
				Principal Name is ASN1_STRING, but not sure at 100%
				Any help will be granted
				*/
				unsigned char* txt;
				ASN1_TYPE* val = name->d.otherName->value;
				ASN1_STRING* str = val->value.asn1_string;
				WLog_DBG(TAG, "Found Kerberos Principal Name ");

				if ((ASN1_STRING_to_UTF8(&txt, str)) < 0)
				{
					WLog_ERR(TAG, "ASN1_STRING_to_UTF8() failed: %s", ERR_error_string(ERR_get_error(), NULL));
				}
				else
				{
					WLog_ERR(TAG, "Adding KPN entry: %s", txt);
					entries[j++] = clone_str((const char*)txt);
				}
			}
		}
	}

	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	ASN1_OBJECT_free(krb5PrincipalName);

	if (j == 0)
	{
		WLog_ERR(TAG, "Certificate does not contain a KPN entry");
		return NULL;
	}

	WLog_ERR(TAG, "end of cert_info_kpn\n");
	return entries;
}

/*
* Extract Certificate's Microsoft Universal Principal Name
*/
static char** cert_info_upn(X509* x509)
{
	int i, j;
	static char* entries[CERT_INFO_SIZE];
	STACK_OF(GENERAL_NAME) *gens;
	GENERAL_NAME* name;
	WLog_DBG(TAG, "Trying to find an Universal Principal Name in certificate");
	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);

	if (!gens)
	{
		WLog_ERR(TAG, "No alternate name extensions found");
		return NULL;
	}

	for (j = 0; j < CERT_INFO_SIZE; j++) entries[j] = NULL;

	for (i = 0, j = 0; (i < sk_GENERAL_NAME_num(gens)) && (j < CERT_INFO_MAX_ENTRIES); i++)
	{
		name = sk_GENERAL_NAME_value(gens, i);

		if (name && name->type == GEN_OTHERNAME)
		{
			/* test for UPN */
			if (OBJ_cmp(name->d.otherName->type_id,
			            OBJ_nid2obj(NID_ms_upn))) continue; /* object is not a UPN */

			WLog_DBG(TAG, "Found Microsoft Universal Principal Name ");

			/* try to extract string and return it */
			if (name->d.otherName->value->type == V_ASN1_UTF8STRING)
			{
				ASN1_UTF8STRING* str = name->d.otherName->value->value.utf8string;
				WLog_DBG(TAG, "Adding UPN NAME entry= %s", str->data);
				entries[j++] = clone_str((const char*)str->data);
			}
			else
			{
				WLog_ERR(TAG, "Found UPN entry is not an utf8string");
			}
		}
	}

	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

	if (j == 0)
	{
		WLog_ERR(TAG, "Certificate does not contain a Microsoft UPN entry");
		return NULL;
	}

	return entries;
}

/*
* Return certificate key algorithm
*/
static char** cert_key_alg(X509* x509)
{
	static char* entries[2] = { NULL, NULL };
	const char* alg = OBJ_nid2ln(
	                      OBJ_obj2nid(x509->cert_info->key->algor->algorithm));
	entries[0] = strdup(alg);
	return entries;
}

/**
* request info on certificate
* @param x509 	Certificate to parse
* @param type 	Information to retrieve
* @return utf-8 string array with provided information
*/
char** cert_info(X509* x509, int type)
{
	if (!x509)
	{
		printf("cert_info : Null certificate provided\n");
		return NULL;
	}

	switch (type)
	{
		case CERT_CN		: /* Certificate Common Name */
			return cert_info_cn(x509);

		case CERT_SUBJECT	: /* Certificate subject */
			return cert_info_subject(x509);

		case CERT_ISSUER	: /* Certificate issuer */
			return cert_info_issuer(x509);

		case CERT_KPN		: /* Kerberos Principal Name */
			return cert_info_kpn(x509);

		case CERT_UPN		: /* Microsoft's Universal Principal Name */
			return cert_info_upn(x509);

		case CERT_KEY_ALG	: /* Certificate signature algorithm */
			return cert_key_alg(x509);

		default           :
			WLog_DBG(TAG, "Invalid info type requested: %d", type);
			return NULL;
	}

	/* should not get here */
	return NULL;
}
