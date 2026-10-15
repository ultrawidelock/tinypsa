/* SPDX-License-Identifier: ISC */
/*
 * Zephyr port: a k_mutex, the chosen zephyr,entropy device, and persistent
 * keys as settings entries named tinypsa/<id in hex>. Key records are stored
 * in the clear. NCS trusted storage sealed them with a key hashed from the
 * device UID, which anyone holding the flash can recompute, so this gives up
 * obfuscation, not secrecy.
 */
#include <zephyr/drivers/entropy.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/printk.h>

#include "port.h"

static K_MUTEX_DEFINE(tp_lock);

void tp_port_lock(void)
{
	k_mutex_lock(&tp_lock, K_FOREVER);
}

void tp_port_unlock(void)
{
	k_mutex_unlock(&tp_lock);
}

int tp_port_entropy(uint8_t *buf, size_t len)
{
	const struct device *dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));

	if (!device_is_ready(dev)) {
		return -1;
	}
	while (len) {
		uint16_t n = MIN(len, UINT16_MAX);

		if (entropy_get_entropy(dev, buf, n)) {
			return -1;
		}
		buf += n;
		len -= n;
	}
	return 0;
}

#if defined(CONFIG_TINYPSA_PERSISTENT_KEYS)
#define NAME_LEN sizeof("tinypsa/00000000")

static void key_name(char name[NAME_LEN], uint32_t id)
{
	snprintk(name, NAME_LEN, "tinypsa/%08x", id);
}

struct rd {
	uint8_t *buf;
	size_t size;
	int len;
};

static int read_one(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		    void *param)
{
	struct rd *rd = param;
	ssize_t n;

	/* Only the exact name; anything under it is not a key record. */
	if (key != NULL) {
		return 0;
	}
	if (len == 0) {
		return 0; /* a deleted entry */
	}
	if (len > rd->size) {
		rd->len = -2;
		return 1;
	}
	n = read_cb(cb_arg, rd->buf, len);
	rd->len = n == (ssize_t)len ? (int)n : -2;
	return 1;
}

int tp_store_read(uint32_t id, uint8_t *buf, size_t size)
{
	char name[NAME_LEN];
	struct rd rd = { buf, size, -1 };

	key_name(name, id);
	settings_load_subtree_direct(name, read_one, &rd);
	return rd.len;
}

int tp_store_write(uint32_t id, const uint8_t *buf, size_t len)
{
	char name[NAME_LEN];

	key_name(name, id);
	return settings_save_one(name, buf, len);
}

int tp_store_erase(uint32_t id)
{
	char name[NAME_LEN];

	key_name(name, id);
	return settings_delete(name);
}
#endif
