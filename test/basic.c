#include <assert.h>
#include <rabin.h>
#include <stdio.h>
#include <string.h>

int
main(void) {
  rabin_t ctx;
  rabin_init(&ctx);

  printf("polynomial        : 0x%llx\n", (unsigned long long) ctx.polynomial);
  printf("polynomial_degree : %d\n", ctx.polynomial_degree);
  printf("polynomial_shift  : %d\n", ctx.polynomial_shift);
  printf("chunk_min         : %u\n", ctx.chunk_min);
  printf("chunk_max         : %u\n", ctx.chunk_max);
  printf("fingerprint_mask  : 0x%llx\n", (unsigned long long) ctx.fingerprint_mask);

  // Verify the tables are non-trivial.
  int mod_nonzero = 0, out_nonzero = 0;

  for (int i = 0; i < 256; i++) {
    if (ctx.mod_table[i]) mod_nonzero++;
    if (ctx.out_table[i]) out_nonzero++;
  }

  printf("mod_table non-zero: %d/256\n", mod_nonzero);
  printf("out_table non-zero: %d/256\n", out_nonzero);

  assert(mod_nonzero >= 200 && out_nonzero >= 200);

  // Two independent contexts must produce identical tables.
  rabin_t ctx2;
  rabin_init(&ctx2);

  assert(
    memcmp(ctx.mod_table, ctx2.mod_table, sizeof(ctx.mod_table)) == 0 &&
    memcmp(ctx.out_table, ctx2.out_table, sizeof(ctx.out_table)) == 0
  );

  // Also verify initial digest is non-zero.
  assert(ctx.digest != 0);
  assert(ctx.digest == ctx2.digest);

  printf("digest: 0x%llx\n", (unsigned long long) ctx.digest);

  // Feed pseudorandom data with small chunk parameters so we can observe many
  // boundaries in a small buffer.
  ctx.chunk_min = 32;
  ctx.chunk_max = 256;
  ctx.fingerprint_mask = (1ULL << 6) - 1; // Average ~64 bytes

  rabin_reset(&ctx);

  uint8_t buf[4096];
  uint32_t seed = 0xDEADBEEF;

  for (int i = 0; i < (int) sizeof(buf); i++) {
    seed = seed * 1103515245 + 12345;
    buf[i] = (uint8_t) (seed >> 16);
  }

  int n, chunks = 0;
  unsigned int total_bytes = 0;
  unsigned int expected_start = 0;

  while ((n = rabin_update(&ctx, buf + ctx.pos, sizeof(buf) - ctx.pos)) > 0) {
    printf(
      "  chunk %2d: start=%u length=%u fp=0x%llx (consumed %d)\n",
      chunks,
      ctx.last_chunk.start,
      ctx.last_chunk.length,
      (unsigned long long) ctx.last_chunk.fingerprint,
      n
    );

    // Verify contiguous coverage.
    assert(ctx.last_chunk.start == expected_start);

    expected_start = ctx.last_chunk.start + ctx.last_chunk.length;
    total_bytes += ctx.last_chunk.length;
    chunks++;
  }

  // Finalize to get trailing data.
  int tail = rabin_final(&ctx);

  if (tail) {
    printf(
      "  tail    : start=%u length=%u fp=0x%llx\n",
      ctx.last_chunk.start,
      ctx.last_chunk.length,
      (unsigned long long) ctx.last_chunk.fingerprint
    );

    assert(ctx.last_chunk.start == expected_start);

    total_bytes += ctx.last_chunk.length;
    chunks++;
  }

  printf(
    "total chunks: %d, total bytes: %u (expected %zu)\n",
    chunks,
    total_bytes,
    sizeof(buf)
  );

  assert(total_bytes == sizeof(buf));

  return 0;
}
