/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/* Host port for tests: no threads, the OS RNG, and an in-memory key store. */
#include <stdlib.h>
#include <string.h>

#include "port.h"
#include "test.h"

#define STORE_SLOTS 16

static struct {
	uint32_t id;
	size_t len;
	uint8_t rec[300];
} store[STORE_SLOTS];

int test_store_fail; /* nonzero makes writes fail */

void tp_port_lock(void)
{
}

void tp_port_unlock(void)
{
}

int tp_port_entropy(uint8_t *buf, size_t len)
{
	arc4random_buf(buf, len);
	return 0;
}

int tp_store_read(uint32_t id, uint8_t *buf, size_t size)
{
	for (int i = 0; i < STORE_SLOTS; i++) {
		if (store[i].id == id && store[i].len) {
			if (store[i].len > size) {
				return -2;
			}
			memcpy(buf, store[i].rec, store[i].len);
			return (int)store[i].len;
		}
	}
	return -1;
}

int tp_store_write(uint32_t id, const uint8_t *buf, size_t len)
{
	int free_slot = -1;

	if (test_store_fail || len > sizeof(store[0].rec)) {
		return -1;
	}
	for (int i = 0; i < STORE_SLOTS; i++) {
		if (store[i].id == id || (free_slot < 0 && store[i].len == 0)) {
			free_slot = i;
			if (store[i].id == id) {
				break;
			}
		}
	}
	if (free_slot < 0) {
		return -1;
	}
	store[free_slot].id = id;
	store[free_slot].len = len;
	memcpy(store[free_slot].rec, buf, len);
	return 0;
}

int tp_store_erase(uint32_t id)
{
	for (int i = 0; i < STORE_SLOTS; i++) {
		if (store[i].id == id) {
			memset(&store[i], 0, sizeof(store[i]));
		}
	}
	return 0;
}
