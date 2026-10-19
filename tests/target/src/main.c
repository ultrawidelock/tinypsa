/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Board entry: the host suite, then a persistent key that must survive a
 * reset. The first boot stores it; the next boot finds it, checks it and
 * destroys it, so boots alternate between the two.
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>

int test_host_main(int argc, char **argv);

#define REBOOT_KEY_ID 0x2F001

static const uint8_t reboot_key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

int main(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0;
	uint8_t out[sizeof(reboot_key)];
	size_t n = 0;
	psa_status_t st;
	int failed = test_host_main(0, NULL);

	st = psa_export_key(REBOOT_KEY_ID, out, sizeof(out), &n);
	if (st == PSA_ERROR_INVALID_HANDLE) {
		psa_set_key_id(&a, REBOOT_KEY_ID);
		psa_set_key_type(&a, PSA_KEY_TYPE_AES);
		psa_set_key_usage_flags(&a, PSA_KEY_USAGE_EXPORT);
		st = psa_import_key(&a, reboot_key, sizeof(reboot_key), &id);
		printf("reboot: key %s; reset to check it\n", st == PSA_SUCCESS ? "stored" : "NOT STORED");
		failed |= st != PSA_SUCCESS;
	} else {
		bool ok = st == PSA_SUCCESS && n == sizeof(reboot_key) &&
			  !memcmp(out, reboot_key, n);

		st = psa_destroy_key(REBOOT_KEY_ID);
		printf("reboot: key %s after reset, destroy %d\n", ok ? "intact" : "WRONG", (int)st);
		failed |= !ok || st != PSA_SUCCESS;
	}
	printf("target: %s\n", failed ? "FAIL" : "PASS");
	return failed;
}
