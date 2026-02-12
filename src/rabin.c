// Copyright (c) 2014, Alexander Neumann <alexander@bumpez.de>
// Copyright (c) 2007, 2008, Geert Bosch <bosch@adacore.com>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//   1. Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//
//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <string.h>

#include "../include/rabin.h"

// Default polynomial
#define RABIN__POLYNOMIAL        0x3DA3358B4DC173LL
#define RABIN__POLYNOMIAL_DEGREE 53
#define RABIN__POLYNOMIAL_SHIFT  (RABIN__POLYNOMIAL_DEGREE - 8) // 45

#define RABIN__AVERAGE_BITS 20
#define RABIN__MASK         ((1 << RABIN__AVERAGE_BITS) - 1)
#define RABIN__MIN_SIZE     (512 * 1024)      // 512 KiB
#define RABIN__MAX_SIZE     (8 * 1024 * 1024) // 8 MiB

/**
 * Return the degree (position of the highest set bit) of polynomial p.
 * Returns -1 for p == 0.
 */
static int
rabin__deg(uint64_t p) {
  uint64_t mask = 0x8000000000000000LL;

  for (int i = 0; i < 64; i++) {
    if ((mask & p) > 0) return 63 - i;

    mask >>= 1;
  }

  return -1;
}

/**
 * Compute the remainder of x divided by p in GF(2).
 */
static uint64_t
rabin__mod(uint64_t x, uint64_t p) {
  while (rabin__deg(x) >= rabin__deg(p)) {
    unsigned int shift = rabin__deg(x) - rabin__deg(p);

    x = x ^ (p << shift);
  }

  return x;
}

/**
 * Append a byte to a hash using the given polynomial.
 */
static uint64_t
rabin__append_byte(uint64_t hash, uint8_t b, uint64_t pol) {
  hash <<= 8;
  hash |= (uint64_t) b;
  return rabin__mod(hash, pol);
}

/**
 * Precompute the `out_table` and `mod_table` for the polynomial stored in
 * `h->polynomial`.
 *
 * out_table[b] = Hash(b || 0 || ... || 0)
 *
 * To slide out the oldest byte `b_0` from the window it suffices to XOR
 * `out_table[b_0]` into the digest, which cancels `b_0`'s contribution after it
 * has shifted through the full window.
 *
 * mod_table[b] = A | B
 *   where A = (b(x) * x^k) mod polynomial
 *     and B = b(x) * x^k
 *
 * The 8 bits above deg(polynomial) determine what happens next and so these
 * bits are used as a lookup to this table. The value is split in two parts:
 * Part A contains the result of the modulus operation, part B is used to cancel
 * out the 8 top bits so that one XOR operation is enough to reduce modulo
 * polynomial.
 */
static void
rabin__precompute_tables(rabin_t *h) {
  for (int b = 0; b < 256; b++) {
    uint64_t hash = 0;

    hash = rabin__append_byte(hash, (uint8_t) b, h->polynomial);

    for (int i = 0; i < RABIN_WINDOW_SIZE - 1; i++) {
      hash = rabin__append_byte(hash, 0, h->polynomial);
    }

    h->out_table[b] = hash;
  }

  int k = rabin__deg(h->polynomial);

  for (int b = 0; b < 256; b++) {
    h->mod_table[b] = rabin__mod(((uint64_t) b) << k, h->polynomial) | ((uint64_t) b) << k;
  }
}

/**
 * Append a byte to the rolling fingerprint using the precomputed `mod_table`.
 */
static void
rabin__append(rabin_t *h, uint8_t b) {
  uint8_t index = (uint8_t) (h->digest >> h->polynomial_shift);
  h->digest <<= 8;
  h->digest |= (uint64_t) b;
  h->digest ^= h->mod_table[index];
}

/**
 * Slide the window: Remove the oldest byte, then append the new byte.
 */
static void
rabin__slide(rabin_t *h, uint8_t b) {
  uint8_t out = h->window[h->wpos];

  h->window[h->wpos] = b;
  h->digest ^= h->out_table[out];
  h->wpos = (h->wpos + 1) % RABIN_WINDOW_SIZE;

  rabin__append(h, b);
}

void
rabin_reset(rabin_t *h) {
  memset(h->window, 0, sizeof(h->window));

  h->wpos = 0;
  h->digest = 0;
  h->count = 0;
  h->digest = 0;

  rabin__slide(h, 1);
}

void
rabin_init(rabin_t *h) {
  memset(h, 0, sizeof(*h));

  h->polynomial = RABIN__POLYNOMIAL;
  h->polynomial_degree = RABIN__POLYNOMIAL_DEGREE;
  h->polynomial_shift = RABIN__POLYNOMIAL_SHIFT;
  h->chunk_min = RABIN__MIN_SIZE;
  h->chunk_max = RABIN__MAX_SIZE;
  h->fingerprint_mask = RABIN__MASK;

  rabin__precompute_tables(h);
  rabin_reset(h);
}

int
rabin_push(rabin_t *h, const uint8_t *buf, unsigned int len) {
  for (unsigned int i = 0; i < len; i++) {
    uint8_t b = *buf++;

    rabin__slide(h, b);

    h->count++;
    h->pos++;

    if ((h->count >= h->chunk_min && ((h->digest & h->fingerprint_mask) == 0)) || h->count >= h->chunk_max) {
      h->last_chunk.offset = h->start;
      h->last_chunk.length = h->count;
      h->last_chunk.fingerprint = h->digest;

      // Preserve position, then reset rolling state.
      unsigned int pos = h->pos;
      rabin_reset(h);
      h->start = pos;
      h->pos = pos;

      return (int) (i + 1);
    }
  }

  return 0;
}

int
rabin_end(rabin_t *h) {
  h->last_chunk.length = h->count;

  if (h->count == 0) {
    h->last_chunk.offset = 0;
    h->last_chunk.fingerprint = 0;
  } else {
    h->last_chunk.offset = h->start;
    h->last_chunk.fingerprint = h->digest;
  }

  return h->count;
}
