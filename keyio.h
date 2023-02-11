enum {
	ASN1_VERS,
	ASN1_N,
	ASN1_E,
	ASN1_D,
	ASN1_P,
	ASN1_Q,
	ASN1_DP,
	ASN1_DQ,
	ASN1_Q1,
	ASN1_LAST,
};

int keywrite(FILE *fp, Bignum *nums[], int nnums);
int keyprint(FILE *fp, char **errstr);
int keyread(FILE *fp, Bignum *nums[], int nnums, char **errstr);
