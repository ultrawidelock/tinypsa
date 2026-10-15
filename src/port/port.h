/* SPDX-License-Identifier: ISC */
/*
 * What the core needs from the platform: one lock, an entropy source, and
 * a store for persistent keys. Zephyr's is src/port/zephyr; host tests
 * bring their own.
 */
#ifndef TINYPSA_PORT_H
#define TINYPSA_PORT_H

#include <stddef.h>
#include <stdint.h>

void tp_port_lock(void);
void tp_port_unlock(void);

/* Full-entropy bytes for seeding the DRBG; 0 on success. */
int tp_port_entropy(uint8_t *buf, size_t len);

/*
 * Persistent key records, opaque to the store. read returns the record
 * length, -1 when the id has no record, or -2 on any other failure;
 * write and erase return 0 on success.
 */
int tp_store_read(uint32_t id, uint8_t *buf, size_t size);
int tp_store_write(uint32_t id, const uint8_t *buf, size_t len);
int tp_store_erase(uint32_t id);

#endif
