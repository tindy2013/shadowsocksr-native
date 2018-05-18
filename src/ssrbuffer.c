/*
 * ssrbuffer.c - buffer interface implement.
 *
 * Copyright (C) 2017 - 2017, ssrlive
 *
 * This file is part of the shadowsocksr-native.
 *
 * shadowsocksr-native is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocksr-native is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include "ssrbuffer.h"

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif


struct buffer_t * buffer_alloc(size_t capacity) {
    struct buffer_t *ptr = calloc(1, sizeof(struct buffer_t));
    ptr->buffer = calloc(capacity, sizeof(char));
    ptr->capacity = capacity;
    return ptr;
}

struct buffer_t * buffer_create_from(const uint8_t *data, size_t len) {
    struct buffer_t *result = buffer_alloc(2048);
    buffer_store(result, data, len);
    return result;
}

int buffer_compare(const struct buffer_t *ptr1, const struct buffer_t *ptr2) {
    if (ptr1==NULL && ptr2==NULL) {
        return 0;
    }
    if (ptr1 && ptr2==NULL) {
        return -1;
    }
    if (ptr1==NULL && ptr2) {
        return 1;
    }
    {
        size_t size = min(ptr1->len, ptr2->len);
        int ret = memcmp(ptr1->buffer, ptr2->buffer, size);
        return (ret != 0) ? ret : ((ptr1->len == ptr2->len) ? 0 : ((size == ptr1->len) ? 1 : -1));
    }
}

void buffer_reset(struct buffer_t *ptr) {
    if (ptr && ptr->buffer) {
        ptr->len = 0;
        memset(ptr->buffer, 0, ptr->capacity);
    }
}

struct buffer_t * buffer_clone(const struct buffer_t *ptr) {
    struct buffer_t *result = NULL;
    if (ptr == NULL) {
        return result;
    }
    result = buffer_alloc(ptr->capacity);
    result->len = ptr->len;
    memcpy(result->buffer, ptr->buffer, ptr->len);
    return result;
}

size_t buffer_realloc(struct buffer_t *ptr, size_t capacity) {
    size_t real_capacity = 0;
    if (ptr == NULL) {
        return real_capacity;
    }
    real_capacity = max(capacity, ptr->capacity);
    if (ptr->capacity < real_capacity) {
        ptr->buffer = (uint8_t *) realloc(ptr->buffer, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

size_t buffer_store(struct buffer_t *ptr, const uint8_t *data, size_t size) {
    size_t result = buffer_realloc(ptr, size);
    memcpy(ptr->buffer, data, size);
    ptr->len = size;
    return min(size, result);
}

void buffer_replace(struct buffer_t *dst, const struct buffer_t *src) {
    if (dst==NULL || src==NULL) { return; }
    buffer_store(dst, src->buffer, src->len);
}

size_t buffer_concatenate(struct buffer_t *ptr, const uint8_t *data, size_t size) {
    size_t result = buffer_realloc(ptr, ptr->len + size);
    memmove(ptr->buffer + ptr->len, data, size);
    ptr->len += size;
    return min(ptr->len, result);
}

size_t buffer_concatenate2(struct buffer_t *dst, const struct buffer_t *src) {
    if (dst==NULL || src==NULL) { return 0; }
    return buffer_concatenate(dst, src->buffer, src->len);
}

void buffer_shorten(struct buffer_t *ptr, size_t begin, size_t len) {
    if (ptr && (0 <= begin && begin <= ptr->len) && (len <= (ptr->len - begin))) {
        if (begin != 0) {
            memmove(ptr->buffer, ptr->buffer + begin, len);
        }
        ptr->len = len;
    }
}

void buffer_free(struct buffer_t *ptr) {
    if (ptr == NULL) {
        return;
    }
    ptr->len = 0;
    ptr->capacity = 0;
    if (ptr->buffer != NULL) {
        free(ptr->buffer);
    }
    free(ptr);
}
