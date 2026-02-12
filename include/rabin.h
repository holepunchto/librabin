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

#ifndef RABIN_H
#define RABIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RABIN_WINDOW_SIZE 64

typedef struct rabin_s rabin_t;
typedef struct rabin_chunk_s rabin_chunk_t;

// Chunk boundary information.
struct rabin_chunk_s {
  unsigned int offset;
  unsigned int length;
  uint64_t fingerprint;
};

// Rabin fingerprint state.
struct rabin_s {
  uint64_t mod_table[256]; // Precomputed polynomial lookup tables
  uint64_t out_table[256];

  uint8_t window[RABIN_WINDOW_SIZE]; // Sliding window
  unsigned int wpos;

  uint64_t digest;    // Rolling fingerprint
  unsigned int count; // Bytes fed since last chunk boundary

  unsigned int pos; // Position tracking within the caller's buffer
  unsigned int start;

  unsigned int chunk_min; // Chunk-size constraints
  unsigned int chunk_max;
  uint64_t fingerprint_mask;

  uint64_t polynomial; // Polynomial configuration
  int polynomial_degree;
  int polynomial_shift;

  rabin_chunk_t last_chunk; // Last chunk boundary found
};

/**
 * Initialise a `rabin_t` with the default polynomial and chunk parameters.
 * The caller may override `chunk_min`, `chunk_max`, and `fingerprint_mask`
 * after this call returns.
 */
void
rabin_init(rabin_t *h);

/**
 * Reset the rolling state (including the initial seed byte) so a new chunk can
 * be scanned.
 */
void
rabin_reset(rabin_t *h);

/**
 * Scan forward in `buf` (of length `len`) for the next chunk boundary.
 *
 * Returns the number of bytes consumed from `buf` when a boundary is found, or
 * 0 if no boundary was found before the end of the buffer.
 *
 * When a boundary is found, `h->last_chunk` is populated with the chunk's start
 * offset, length, and fingerprint at the cut point.
 */
int
rabin_push(rabin_t *h, const uint8_t *buf, unsigned int len);

/**
 * Obtain the trailing bytes that did not form a complete chunk.
 */
int
rabin_end(rabin_t *h);

#ifdef __cplusplus
}
#endif

#endif // RABIN_H
