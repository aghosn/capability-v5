// SPDX-License-Identifier: GPL-2.0
/*
 * test_attestation — userspace test for signed attestation with user binding.
 *
 * Build: cc -Wall -O2 -I../inc -o test_attestation test_attestation.c -lcrypto
 * Usage: sudo ./test_attestation
 *
 * Tests:
 *   1. Unsigned attestation (nonce=0): verifies report structure returned.
 *   2. Signed attestation (nonce≠0, user_pub_key): verifies:
 *      - Nonce and user_pub_key echoed correctly
 *      - Ed25519 signature over SHA-256(report || nonce || user_pub_key)
 *      - TPM RSA-2048 signature over TPMS_ATTEST blob (if TPM present)
 *
 * Requires: libcrypto (OpenSSL) for Ed25519 and RSA verification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

/* ── Mirror definitions from thhv.h ─────────────────────────────────────── */

#define THHV_IOCTL_MAGIC  0xB8

struct thhv_attest_self {
	uint8_t  nonce[32];
	uint8_t  user_pub_key[32];
	uint64_t report_size;
	uint8_t  report_buf[4096];
};

#define THHV_ATTEST_SELF \
	_IOWR(THHV_IOCTL_MAGIC, 0x05, struct thhv_attest_self)

/* AttestReport (40 bytes, matches domcomm.rs) */
#define ATTEST_REPORT_SIZE 40

/* SignedAttestReport fixed header (208 bytes, matches domcomm.rs) */
struct signed_attest_hdr {
	/* AttestReport (40 bytes) */
	uint64_t domain_id;
	uint32_t flags;
	uint32_t num_vps;
	uint32_t api_flags;
	uint32_t nr_mem_caps;
	uint32_t nr_dom_caps;
	uint32_t nr_pa_entries;
	uint16_t chunk_index;
	uint16_t total_chunks;
	uint32_t reserved_report;

	/* Signature + keys */
	uint8_t  signature[64];       /* Ed25519 signature */
	uint8_t  pub_key[32];         /* capavisor Ed25519 pub key */
	uint8_t  nonce[32];           /* echoed nonce */
	uint8_t  user_pub_key[32];    /* echoed user pub key */

	/* TPM quote sizes */
	uint16_t tpm_quote_size;
	uint16_t tpm_sig_size;
	uint16_t ak_pub_size;
	uint16_t reserved;
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void fill_random(uint8_t *buf, size_t len)
{
	srand((unsigned)time(NULL) ^ getpid());
	for (size_t i = 0; i < len; i++)
		buf[i] = rand() & 0xFF;
}

static void hexdump(const char *label, const uint8_t *buf, size_t len)
{
	printf("  %s: ", label);
	for (size_t i = 0; i < len && i < 16; i++)
		printf("%02x", buf[i]);
	if (len > 16)
		printf("...");
	printf(" (%zu bytes)\n", len);
}

/* ── Ed25519 verification ────────────────────────────────────────────────── */

/*
 * Capavisor signs: ed25519_sign(SHA-256(report[40] || nonce[32] || user_pub_key[32]))
 * So the "message" for Ed25519 verify is the 32-byte SHA-256 digest.
 */
static int verify_ed25519(const struct signed_attest_hdr *hdr)
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	uint8_t digest[32];
	unsigned int digest_len = 0;
	EVP_MD_CTX *sha_ctx = NULL;
	int ret = 0;

	/* Reconstruct: SHA-256(report || nonce || user_pub_key) */
	sha_ctx = EVP_MD_CTX_new();
	if (!sha_ctx) return -1;
	EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(sha_ctx, hdr, ATTEST_REPORT_SIZE);
	EVP_DigestUpdate(sha_ctx, hdr->nonce, 32);
	EVP_DigestUpdate(sha_ctx, hdr->user_pub_key, 32);
	EVP_DigestFinal_ex(sha_ctx, digest, &digest_len);
	EVP_MD_CTX_free(sha_ctx);

	/* Create Ed25519 public key from raw bytes. */
	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
					   hdr->pub_key, 32);
	if (!pkey) {
		printf("  FAIL: EVP_PKEY_new_raw_public_key failed\n");
		ERR_print_errors_fp(stdout);
		return -1;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		printf("  FAIL: EVP_DigestVerifyInit failed\n");
		ret = -1;
		goto out;
	}

	/*
	 * Ed25519 verify: the "message" is the 32-byte SHA-256 digest
	 * (that's what the capavisor passed to ed25519_dalek::sign).
	 */
	if (EVP_DigestVerify(ctx, hdr->signature, 64,
			     digest, sizeof(digest)) != 1) {
		printf("  FAIL: Ed25519 signature INVALID\n");
		hexdump("digest", digest, 32);
		ERR_print_errors_fp(stdout);
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ret;
}

/* ── TPM RSA-2048 signature verification ─────────────────────────────────── */

/*
 * TPM2_Quote signs SHA-256(TPMS_ATTEST) with RSASSA-PKCS1-v1.5.
 *
 * TPMT_SIGNATURE layout (tpm_sig blob):
 *   [0..2]  sigAlg   = 0x0014 (TPM_ALG_RSASSA)
 *   [2..4]  hashAlg  = 0x000B (TPM_ALG_SHA256)
 *   [4..6]  sigSize  = 256 (big-endian)
 *   [6..262] RSA signature bytes (256)
 *
 * AK public key: 256-byte RSA modulus, exponent = 65537.
 */
static int verify_tpm_quote(const uint8_t *tpm_quote, uint16_t quote_size,
			    const uint8_t *tpm_sig,   uint16_t sig_size,
			    const uint8_t *ak_pub,    uint16_t ak_size)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *key_ctx = NULL;
	BIGNUM *n = NULL, *e = NULL;
	int ret = -1;

	if (sig_size < 6) {
		printf("  FAIL: tpm_sig too small (%u)\n", sig_size);
		return -1;
	}

	/* Parse TPMT_SIGNATURE header. */
	uint16_t sig_alg = (tpm_sig[0] << 8) | tpm_sig[1];
	uint16_t hash_alg = (tpm_sig[2] << 8) | tpm_sig[3];
	uint16_t rsa_sig_size = (tpm_sig[4] << 8) | tpm_sig[5];

	printf("  tpm_sig: alg=0x%04x hash=0x%04x rsa_size=%u\n",
	       sig_alg, hash_alg, rsa_sig_size);

	if (sig_alg != 0x0014) {  /* TPM_ALG_RSASSA */
		printf("  FAIL: unexpected sigAlg 0x%04x\n", sig_alg);
		return -1;
	}
	if (hash_alg != 0x000B) {  /* TPM_ALG_SHA256 */
		printf("  FAIL: unexpected hashAlg 0x%04x\n", hash_alg);
		return -1;
	}
	if (rsa_sig_size != 256 || sig_size < 6 + 256) {
		printf("  FAIL: RSA sig size mismatch (%u)\n", rsa_sig_size);
		return -1;
	}

	const uint8_t *rsa_sig = tpm_sig + 6;

	/* Build RSA public key from modulus + e=65537 (OpenSSL 3.0 API). */
	n = BN_bin2bn(ak_pub, ak_size, NULL);
	e = BN_new();
	BN_set_word(e, 65537);

	bld = OSSL_PARAM_BLD_new();
	if (!bld) goto out;
	OSSL_PARAM_BLD_push_BN(bld, "n", n);
	OSSL_PARAM_BLD_push_BN(bld, "e", e);
	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) goto out;

	key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!key_ctx) goto out;
	if (EVP_PKEY_fromdata_init(key_ctx) != 1) goto out;
	if (EVP_PKEY_fromdata(key_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
		printf("  FAIL: EVP_PKEY_fromdata failed\n");
		ERR_print_errors_fp(stdout);
		goto out;
	}

	/* Verify RSASSA-PKCS1-v1.5-SHA256(tpms_attest). */
	ctx = EVP_MD_CTX_new();
	if (!ctx) goto out;

	if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey) != 1) {
		printf("  FAIL: RSA DigestVerifyInit failed\n");
		ERR_print_errors_fp(stdout);
		goto out;
	}

	if (EVP_DigestVerifyUpdate(ctx, tpm_quote, quote_size) != 1) {
		printf("  FAIL: RSA DigestVerifyUpdate failed\n");
		goto out;
	}

	if (EVP_DigestVerifyFinal(ctx, rsa_sig, 256) != 1) {
		printf("  FAIL: TPM RSA signature INVALID\n");
		ERR_print_errors_fp(stdout);
		goto out;
	}

	ret = 0;

out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_CTX_free(key_ctx);
	EVP_PKEY_free(pkey);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(n);
	BN_free(e);
	return ret;
}

/* ── Tests ───────────────────────────────────────────────────────────────── */

static int test_unsigned(int fd)
{
	struct thhv_attest_self as;
	int ret;

	printf("=== Test 1: Unsigned attestation (nonce=0) ===\n");

	memset(&as, 0, sizeof(as));

	ret = ioctl(fd, THHV_ATTEST_SELF, &as);
	if (ret < 0) {
		printf("  FAIL: ioctl returned %d (errno=%d: %s)\n",
		       ret, errno, strerror(errno));
		return 1;
	}

	printf("  report_size = %lu bytes\n", (unsigned long)as.report_size);

	if (as.report_size == 0) {
		printf("  FAIL: report_size is 0\n");
		return 1;
	}

	printf("  PASS: unsigned attestation returned %lu bytes\n",
	       (unsigned long)as.report_size);
	return 0;
}

static int test_signed(int fd)
{
	struct thhv_attest_self as;
	struct signed_attest_hdr *hdr;
	int ret;
	uint8_t test_nonce[32];
	uint8_t test_pubkey[32];

	printf("\n=== Test 2: Signed attestation (nonce + user_pub_key) ===\n");

	memset(&as, 0, sizeof(as));

	/* Generate test nonce and user pub key. */
	fill_random(test_nonce, 32);
	fill_random(test_pubkey, 32);
	/* Ensure at least one byte is non-zero (triggers signed path). */
	test_nonce[0] |= 0x01;

	memcpy(as.nonce, test_nonce, 32);
	memcpy(as.user_pub_key, test_pubkey, 32);

	ret = ioctl(fd, THHV_ATTEST_SELF, &as);
	if (ret < 0) {
		printf("  FAIL: ioctl returned %d (errno=%d: %s)\n",
		       ret, errno, strerror(errno));
		return 1;
	}

	printf("  report_size = %lu bytes\n", (unsigned long)as.report_size);

	if (as.report_size < sizeof(struct signed_attest_hdr)) {
		printf("  FAIL: report too small (%lu < %zu)\n",
		       (unsigned long)as.report_size,
		       sizeof(struct signed_attest_hdr));
		return 1;
	}

	hdr = (struct signed_attest_hdr *)as.report_buf;

	/* Check domain_id is sane (dom0 = 0). */
	printf("  domain_id = %lu\n", (unsigned long)hdr->domain_id);
	if (hdr->domain_id != 0) {
		printf("  WARN: expected domain_id=0 for dom0\n");
	}

	/* Verify nonce is echoed back. */
	if (memcmp(hdr->nonce, test_nonce, 32) != 0) {
		printf("  FAIL: nonce mismatch!\n");
		hexdump("sent    ", test_nonce, 32);
		hexdump("received", hdr->nonce, 32);
		return 1;
	}
	printf("  PASS: nonce echoed correctly\n");

	/* Verify user_pub_key is echoed back. */
	if (memcmp(hdr->user_pub_key, test_pubkey, 32) != 0) {
		printf("  FAIL: user_pub_key mismatch!\n");
		hexdump("sent    ", test_pubkey, 32);
		hexdump("received", hdr->user_pub_key, 32);
		return 1;
	}
	printf("  PASS: user_pub_key echoed correctly\n");

	/* Verify Ed25519 signature cryptographically. */
	printf("  Verifying Ed25519 signature...\n");
	hexdump("signature", hdr->signature, 64);
	hexdump("capavisor_pub_key", hdr->pub_key, 32);

	if (verify_ed25519(hdr) != 0) {
		printf("  FAIL: Ed25519 signature verification failed\n");
		return 1;
	}
	printf("  PASS: Ed25519 signature VALID\n");

	/* Check TPM quote fields. */
	printf("  tpm_quote_size = %u\n", hdr->tpm_quote_size);
	printf("  tpm_sig_size   = %u\n", hdr->tpm_sig_size);
	printf("  ak_pub_size    = %u\n", hdr->ak_pub_size);

	if (hdr->tpm_quote_size > 0) {
		size_t expected_total = sizeof(struct signed_attest_hdr)
			+ hdr->tpm_quote_size
			+ hdr->tpm_sig_size
			+ hdr->ak_pub_size;

		printf("  TPM quote present! total expected = %zu, got = %lu\n",
		       expected_total, (unsigned long)as.report_size);

		if (as.report_size < expected_total) {
			printf("  FAIL: report too small for TPM data\n");
			return 1;
		}

		uint8_t *tpm_quote = as.report_buf + sizeof(struct signed_attest_hdr);
		uint8_t *tpm_sig = tpm_quote + hdr->tpm_quote_size;
		uint8_t *ak_pub = tpm_sig + hdr->tpm_sig_size;

		hexdump("tpm_quote", tpm_quote, hdr->tpm_quote_size);
		hexdump("tpm_sig  ", tpm_sig, hdr->tpm_sig_size);
		hexdump("ak_pub   ", ak_pub, hdr->ak_pub_size);

		/* Verify TPM RSA-2048 signature cryptographically. */
		printf("  Verifying TPM RSA-2048 signature...\n");
		if (verify_tpm_quote(tpm_quote, hdr->tpm_quote_size,
				     tpm_sig, hdr->tpm_sig_size,
				     ak_pub, hdr->ak_pub_size) != 0) {
			printf("  FAIL: TPM RSA signature verification failed\n");
			return 1;
		}
		printf("  PASS: TPM RSA signature VALID\n");
	} else {
		printf("  INFO: no TPM quote (tpm_quote_size=0)\n");
	}

	printf("  PASS: signed attestation structure valid\n");
	return 0;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
	int fd, failures = 0;

	fd = open("/dev/thhv", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Failed to open /dev/thhv: %s\n", strerror(errno));
		fprintf(stderr, "Is thhv.ko loaded? (sudo insmod /opt/bins/thhv/thhv.ko)\n");
		return 1;
	}

	failures += test_unsigned(fd);
	failures += test_unsigned(fd);
	failures += test_signed(fd);

	close(fd);

	printf("\n%s: %d test(s) failed\n",
	       failures ? "FAIL" : "ALL TESTS PASSED", failures);
	return failures ? 1 : 0;
}
