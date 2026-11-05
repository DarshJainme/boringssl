// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicabl e law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gtest/gtest.h>

#include "hqc.h"
#include "../fipsmodule/hqc/params.h"
#include "../fipsmodule/hqc/vector.h"
#include "../fipsmodule/hqc/shake.h"
#include "../fipsmodule/hqc/gf2x.h"
#include "../fipsmodule/hqc/gf.h"
#include "../fipsmodule/hqc/fft.h"
#include "../fipsmodule/hqc/reed_solomon.h"
#include "../fipsmodule/hqc/reed_muller.h"
#include "../fipsmodule/hqc/code.h"
#include "../fipsmodule/hqc/parsing.h"

#include <string.h>

namespace {

uint8_t ReferenceGfMul(uint8_t a, uint8_t b) {
    uint16_t result = 0;
    uint16_t multiplicand = a;

    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= multiplicand;
        }

        b >>= 1;
        multiplicand <<= 1;

        if (multiplicand & 0x100) {
            multiplicand ^= PARAM_GF_POLY;
        }
    }

    return static_cast<uint8_t>(result);
}

uint16_t EvaluatePolynomial(const uint16_t *coeffs,
                            size_t coeff_count, uint16_t x) {
    uint16_t result = 0;

    for (size_t i = coeff_count; i > 0; --i) {
        result = bssl::gf_mul(result, x) ^ coeffs[i - 1];
    }

    return result;
}

uint16_t FFTPointForIndex(size_t index) {
    const size_t half = 1U << (PARAM_M - 1);

    size_t subset = index % half;
    uint16_t x = (index >= half) ? 1 : 0;

    for (size_t bit = 0; bit < PARAM_M - 1; ++bit) {
        if (subset & (1U << bit)) {
            x ^= 1U << (PARAM_M - 1 - bit);
        }
    }

    return x;
}

bool TestReedSolomonCorrection(size_t error_count) {
    uint64_t msg[VEC_K_SIZE_64] = {};
    uint64_t cdw[VEC_N1_SIZE_64] = {};
    uint64_t corrupted[VEC_N1_SIZE_64] = {};
    uint64_t decoded[VEC_K_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_K; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(i * 17 + 0x31);
    }

     bssl::reed_solomon_encode(cdw, msg);

    memcpy(corrupted, cdw, PARAM_N1);

    uint8_t *corrupted_bytes =
        reinterpret_cast<uint8_t *>(corrupted);

    for (size_t i = 0; i < error_count; ++i) {
        size_t position = (i * 7 + 3) % PARAM_N1;
        uint8_t error_value = static_cast<uint8_t>(i * 29 + 1);

        corrupted_bytes[position] ^= error_value;
    }

    bssl::reed_solomon_decode(decoded, corrupted);

    return memcmp(decoded, msg, PARAM_K) == 0;
}

}  // namespace

namespace bssl {

TEST(HQCTest, Basic) {
  EXPECT_TRUE(HQC_test());
}

TEST(HQCTest, Parameters) {
  EXPECT_EQ(PARAM_N, 17669);
  EXPECT_EQ(PARAM_N1, 46);
  EXPECT_EQ(PARAM_N2, 384);
  EXPECT_EQ(PARAM_N1N2, 17664);

  EXPECT_EQ(VEC_N_SIZE_BYTES, 2209);
  EXPECT_EQ(VEC_N_SIZE_64, 277);
  EXPECT_EQ(VEC_N1N2_SIZE_BYTES, 2208);
  EXPECT_EQ(VEC_N1N2_SIZE_64, 276);

  EXPECT_EQ(PUBLIC_KEY_BYTES, 2249);
  EXPECT_EQ(SECRET_KEY_BYTES, 2289);
  EXPECT_EQ(CIPHERTEXT_BYTES, 4497);
  EXPECT_EQ(SHARED_SECRET_BYTES, 64);

  EXPECT_EQ(RED_MASK, 31u);
}

TEST(HQCTest, VectorAdd) {
  uint64_t v1[VEC_N_SIZE_64] = {};
  uint64_t v2[VEC_N_SIZE_64] = {};
  uint64_t out[VEC_N_SIZE_64] = {};
  uint64_t expected[VEC_N_SIZE_64] = {};

  for (size_t i = 0; i < VEC_N_SIZE_64; ++i) {
    v1[i] = UINT64_C(0x123456789ABCDEF0) + i;
    v2[i] = UINT64_C(0xFEDCBA9876543210) ^ i;
    expected[i] = v1[i] ^ v2[i];
  }

  vect_add(out, v1, v2, VEC_N_SIZE_64);
  EXPECT_EQ(0, memcmp(out, expected, sizeof(out)));
}

TEST(HQCTest, VectorCompare) {
  uint8_t v1[64] = {};
  uint8_t v2[64] = {};

  for (size_t i = 0; i < sizeof(v1); ++i) {
    v1[i] = static_cast<uint8_t>(i + 1);
    v2[i] = static_cast<uint8_t>(i + 1);
  }

  // Identical vectors must return 0
  EXPECT_EQ(0, vect_compare(v1, v2, sizeof(v1)));

  // A single byte difference must return non-zero
  v2[31] ^= 0x01;
  EXPECT_NE(0, vect_compare(v1, v2, sizeof(v1)));
}

TEST(HQCTest, VectorResize) {
  uint64_t in[VEC_N1N2_SIZE_64] = {};
  uint64_t out[VEC_N1N2_SIZE_64] = {};

  for (size_t i = 0; i < VEC_N1N2_SIZE_64; ++i) {
    in[i] = UINT64_C(0xFFFFFFFFFFFFFFFF);
  }

  // 1. Truncation mode: size_o < size_v with non-multiple of 64 bits
  uint32_t target_bits = PARAM_N1N2 - 13;
  vect_resize(out, target_bits, in, PARAM_N1N2);

  // Lower words must remain fully set
  for (size_t i = 0; i < VEC_N1N2_SIZE_64 - 1; ++i) {
    EXPECT_EQ(UINT64_C(0xFFFFFFFFFFFFFFFF), out[i]);
  }

  // 2. Expansion / Equal size mode: size_o >= size_v
  uint64_t out_expand[VEC_N1N2_SIZE_64] = {};
  vect_resize(out_expand, PARAM_N1N2, in, PARAM_N1N2);
  EXPECT_EQ(0, memcmp(in, out_expand, VEC_N1N2_SIZE_BYTES));
}

TEST(HQCTest, ShakeSeedExpander) {
  uint8_t seed[32];

  for (size_t i = 0; i < sizeof(seed); i++) {
    seed[i] = static_cast<uint8_t>(i);
  }

  const uint8_t expected[] = {
      0x89, 0xc8, 0xe9, 0x06, 0xab, 0xee, 0xe8, 0xae,
      0x64, 0x13, 0x3c, 0x55, 0xe8, 0x7d, 0x99, 0x09,
      0xa3, 0x80, 0x8b, 0xf5, 0xd8, 0x0f, 0x96, 0x92
  };

  bssl::shake_state state;
  uint8_t output1[13];
  uint8_t output2[8];

  bssl::seedexpander_init(&state, seed, sizeof(seed));

  // First call requests 13 bytes but consumes 16 bytes.
  bssl::seedexpander(&state, output1, sizeof(output1));

  // Second call starts at byte 16.
  bssl::seedexpander(&state, output2, sizeof(output2));

  EXPECT_EQ(0, memcmp(output1, expected, 13));
  EXPECT_EQ(0, memcmp(output2, expected + 16, 8));
}

TEST(HQCTest, Shake256DomainSeparation) {
  uint8_t input[32];

  for (size_t i = 0; i < sizeof(input); i++) {
    input[i] = static_cast<uint8_t>(i);
  }

  const uint8_t expected[64] = {
      0x7a, 0xa0, 0x3a, 0xfa, 0xa1, 0xc5, 0x68, 0x93,
      0x20, 0x75, 0x5b, 0x42, 0x4e, 0x98, 0xcb, 0x1f,
      0x29, 0x0e, 0x04, 0xc9, 0x2f, 0x28, 0xc4, 0x26,
      0x8b, 0xb2, 0x9e, 0xba, 0xc2, 0x97, 0x8a, 0x5a,
      0x8b, 0xee, 0x71, 0x73, 0xe1, 0x0c, 0xb5, 0x52,
      0x8b, 0xb1, 0xe5, 0xf5, 0x38, 0x83, 0x55, 0x6a,
      0xfb, 0x98, 0x0f, 0x70, 0x35, 0x77, 0x97, 0x43,
      0xba, 0xc2, 0x8b, 0xd6, 0x9e, 0x6e, 0x14, 0x9a
  };

  bssl::shake_state state;
  uint8_t output[64];

  bssl::shake256_512_ds(&state, output, input, sizeof(input), 3);

  EXPECT_EQ(0, memcmp(output, expected, sizeof(expected)));
}


TEST(HQCTest, ShakePRNGDeterministic) {
  uint8_t entropy[32] = {};
  uint8_t personalization[16] = {};

  for (size_t i = 0; i < sizeof(entropy); i++) {
    entropy[i] = static_cast<uint8_t>(i);
  }

  for (size_t i = 0; i < sizeof(personalization); i++) {
    personalization[i] = static_cast<uint8_t>(i + 32);
  }

  bssl::shake_state state1, state2;
  uint8_t output1[64], output2[64];

  bssl::shake_prng_init(&state1, entropy, personalization,
                        sizeof(entropy), sizeof(personalization));

  bssl::shake_prng_init(&state2, entropy, personalization,
                        sizeof(entropy), sizeof(personalization));

  bssl::shake_prng(&state1, output1, sizeof(output1));
  bssl::shake_prng(&state2, output2, sizeof(output2));

  EXPECT_EQ(0, memcmp(output1, output2, sizeof(output1)));
}

TEST(HQCTest, ShakePRNGDifferentInputs) {
  uint8_t entropy1[32] = {};
  uint8_t entropy2[32] = {};
  uint8_t personalization[16] = {};

  entropy2[0] = 1;

  bssl::shake_state state1, state2;
  uint8_t output1[64], output2[64];

  bssl::shake_prng_init(&state1, entropy1, personalization, 32, 16);
  bssl::shake_prng_init(&state2, entropy2, personalization, 32, 16);

  bssl::shake_prng(&state1, output1, sizeof(output1));
  bssl::shake_prng(&state2, output2, sizeof(output2));

  EXPECT_NE(0, memcmp(output1, output2, sizeof(output1)));
}

TEST(HQCTest, ShakePRNGChunkedOutput) {
  uint8_t entropy[32] = {};
  uint8_t personalization[16] = {};

  bssl::shake_state state1, state2;
  uint8_t full[64], first[20], second[44];

  bssl::shake_prng_init(&state1, entropy, personalization, 32, 16);
  bssl::shake_prng_init(&state2, entropy, personalization, 32, 16);

  bssl::shake_prng(&state1, full, sizeof(full));

  bssl::shake_prng(&state2, first, sizeof(first));
  bssl::shake_prng(&state2, second, sizeof(second));

  EXPECT_EQ(0, memcmp(full, first, sizeof(first)));
  EXPECT_EQ(0, memcmp(full + 20, second, sizeof(second)));
}

TEST(HQCTest, Shake256DifferentDomains) {
  uint8_t input[32] = {};

  for (size_t i = 0; i < sizeof(input); i++) {
    input[i] = static_cast<uint8_t>(i);
  }

  bssl::shake_state state1, state2;
  uint8_t output1[64], output2[64];

  bssl::shake256_512_ds(&state1, output1, input, sizeof(input), 3);
  bssl::shake256_512_ds(&state2, output2, input, sizeof(input), 4);

  EXPECT_NE(0, memcmp(output1, output2, sizeof(output1)));
}

TEST(HQCTest, ShakeSeedExpanderChunkedOutput) {
  uint8_t seed[32] = {};

  for (size_t i = 0; i < sizeof(seed); i++) {
    seed[i] = static_cast<uint8_t>(i);
  }

  bssl::shake_state state1, state2;
  uint8_t full[32], first[8], second[24];

  bssl::seedexpander_init(&state1, seed, sizeof(seed));
  bssl::seedexpander_init(&state2, seed, sizeof(seed));

  bssl::seedexpander(&state1, full, sizeof(full));

  bssl::seedexpander(&state2, first, sizeof(first));
  bssl::seedexpander(&state2, second, sizeof(second));

  EXPECT_EQ(0, memcmp(full, first, sizeof(first)));
  EXPECT_EQ(0, memcmp(full + 8, second, sizeof(second)));
}


TEST(HQCTest, ShakeSeedExpanderAlignment) {
  uint8_t seed[32] = {};

  for (size_t i = 0; i < sizeof(seed); i++) {
    seed[i] = static_cast<uint8_t>(i);
  }

  bssl::shake_state state1, state2;

  uint8_t output1[13], output2[8];
  uint8_t reference[24];

  bssl::seedexpander_init(&state1, seed, sizeof(seed));
  bssl::seedexpander_init(&state2, seed, sizeof(seed));

  bssl::seedexpander(&state1, output1, sizeof(output1));
  bssl::seedexpander(&state1, output2, sizeof(output2));

  bssl::seedexpander(&state2, reference, sizeof(reference));

  EXPECT_EQ(0, memcmp(output1, reference, 13));
  EXPECT_EQ(0, memcmp(output2, reference + 16, 8));
}

TEST(HQCTest, ShakePRNGKnownAnswer) {
  uint8_t entropy[32];
  uint8_t personalization[16];

  for (size_t i = 0; i < sizeof(entropy); i++) {
    entropy[i] = static_cast<uint8_t>(i);
  }

  for (size_t i = 0; i < sizeof(personalization); i++) {
    personalization[i] = static_cast<uint8_t>(i + 32);
  }

  // Exact 64-byte SHAKE-256 output for PRNG_DOMAIN = 1
  const uint8_t expected[64] = {
      0x42, 0xc6, 0x67, 0xa1, 0x86, 0x39, 0x0f, 0x26,
      0xc8, 0xf0, 0x24, 0xd3, 0x1d, 0x5f, 0xe3, 0xd2,
      0x01, 0x45, 0xbc, 0x2f, 0xcc, 0xf2, 0x6c, 0x86,
      0x5e, 0x20, 0xdf, 0x76, 0x26, 0xce, 0xf0, 0x9e,
      0x4d, 0x9e, 0xad, 0xd2, 0x63, 0xd9, 0x5e, 0xde,
      0x93, 0x4a, 0x74, 0xb3, 0x72, 0x1e, 0xaa, 0xb0,
      0xa8, 0x4c, 0x24, 0x20, 0x15, 0xb6, 0x05, 0x75,
      0xd7, 0xc1, 0x1a, 0xb9, 0x37, 0x1e, 0xef, 0x36
  };

  bssl::shake_state state;
  uint8_t output[64];

  bssl::shake_prng_init(&state, entropy, personalization,
                        sizeof(entropy), sizeof(personalization));

  bssl::shake_prng(&state, output, sizeof(output));

  EXPECT_EQ(0, memcmp(output, expected, sizeof(expected)));
}

TEST(HQCTest, GF2xMultiplyByZero) {
  uint64_t a[VEC_N_SIZE_64] = {};
  uint64_t zero[VEC_N_SIZE_64] = {};
  uint64_t out[VEC_N_SIZE_64] = {};

  a[0] = 0x123456789abcdef0ULL;
  a[1] = 0xaaaaaaaaaaaaaaaaULL;

  vect_mul(out, a, zero);

  EXPECT_EQ(0, memcmp(out, zero, sizeof(out)));

  vect_mul(out, zero, a);

  EXPECT_EQ(0, memcmp(out, zero, sizeof(out)));
}

TEST(HQCTest, GF2xMultiplyByOne) {
  uint64_t a[VEC_N_SIZE_64] = {};
  uint64_t one[VEC_N_SIZE_64] = {};
  uint64_t out[VEC_N_SIZE_64] = {};

  for (size_t i = 0; i < VEC_N_SIZE_64; ++i) {
    a[i] = UINT64_C(0xd1b54a32d192ed03) * (i + 1);
  }

  a[VEC_N_SIZE_64 - 1] &= RED_MASK;
  one[0] = 1;

  vect_mul(out, a, one);

  EXPECT_EQ(0, memcmp(out, a, sizeof(out)));

  vect_mul(out, one, a);

  EXPECT_EQ(0, memcmp(out, a, sizeof(out)));
}

TEST(HQCTest, GF2xMultiplication) {
  uint64_t a[VEC_N_SIZE_64] = {};
  uint64_t b[VEC_N_SIZE_64] = {};
  uint64_t expected[VEC_N_SIZE_64] = {};
  uint64_t actual[VEC_N_SIZE_64] = {};

  a[0] = UINT64_C(0x8000000000000001);
  b[0] = UINT64_C(0x0000000000000003);

  expected[0] = UINT64_C(0x8000000000000003);
  expected[1] = 1;

  vect_mul(actual, a, b);

  EXPECT_EQ(0, memcmp(actual, expected, sizeof(actual)));
}

TEST(HQCTest, GF2xModularReduction) {
  uint64_t a[VEC_N_SIZE_64] = {};
  uint64_t b[VEC_N_SIZE_64] = {};
  uint64_t expected[VEC_N_SIZE_64] = {};
  uint64_t actual[VEC_N_SIZE_64] = {};

  // A(X) = X^(PARAM_N - 1)
  a[(PARAM_N - 1) / 64] =
      UINT64_C(1) << ((PARAM_N - 1) % 64);

  // B(X) = X
  b[0] = 2;

  // Expected result = 1
  expected[0] = 1;

  vect_mul(actual, a, b);

  EXPECT_EQ(0, memcmp(actual, expected, sizeof(actual)));
}

TEST(HQCTest, GF2xHighestDegreeWraparound) {
  uint64_t a[VEC_N_SIZE_64] = {};
  uint64_t b[VEC_N_SIZE_64] = {};
  uint64_t expected[VEC_N_SIZE_64] = {};
  uint64_t actual[VEC_N_SIZE_64] = {};

  uint32_t highest_bit = PARAM_N - 1;

  a[highest_bit / 64] =
      UINT64_C(1) << (highest_bit % 64);

  b[highest_bit / 64] =
      UINT64_C(1) << (highest_bit % 64);

  // 17667 = 276 * 64 + 3
  expected[276] = UINT64_C(1) << 3;

  vect_mul(actual, a, b);

  EXPECT_EQ(0, memcmp(actual, expected, sizeof(actual)));
}

TEST(HQCTest, GF2xAliasing) {
  uint64_t a[VEC_N_SIZE_64] = {};
  uint64_t b[VEC_N_SIZE_64] = {};
  uint64_t expected[VEC_N_SIZE_64] = {};
  uint64_t alias_a[VEC_N_SIZE_64] = {};
  uint64_t alias_b[VEC_N_SIZE_64] = {};

  for (size_t i = 0; i < VEC_N_SIZE_64; ++i) {
    a[i] = UINT64_C(0x9e3779b97f4a7c15) * (i + 1);
    b[i] = UINT64_C(0xd1b54a32d192ed03) * (i + 1);
  }

  a[VEC_N_SIZE_64 - 1] &= RED_MASK;
  b[VEC_N_SIZE_64 - 1] &= RED_MASK;

  // Calculate the expected output without aliasing.
  vect_mul(expected, a, b);

  // Output aliases the first input.
  memcpy(alias_a, a, sizeof(alias_a));
  vect_mul(alias_a, alias_a, b);

  EXPECT_EQ(0, memcmp(alias_a, expected, sizeof(expected)));

  // Output aliases the second input.
  memcpy(alias_b, b, sizeof(alias_b));
  vect_mul(alias_b, a, alias_b);

  EXPECT_EQ(0, memcmp(alias_b, expected, sizeof(expected)));
}
TEST(HQCTest, GFMultiplicationExhaustive) {
    for (uint16_t a = 0; a < 256; ++a) {
        for (uint16_t b = 0; b < 256; ++b) {
            uint8_t expected = ReferenceGfMul(
                static_cast<uint8_t>(a),
                static_cast<uint8_t>(b));

            ASSERT_EQ(expected, gf_mul(a, b))
                << "a = " << a << ", b = " << b;
        }
    }
}
TEST(HQCTest, GFSquare) {
    for (uint16_t a = 0; a < 256; ++a) {
        EXPECT_EQ(gf_mul(a, a), gf_square(a))
            << "a = " << a;
    }
}

TEST(HQCTest, GFInverse) {
    EXPECT_EQ(0, gf_inverse(0));

    for (uint16_t a = 1; a < 256; ++a) {
        uint16_t inverse = gf_inverse(a);

        EXPECT_EQ(1, gf_mul(a, inverse))
            << "a = " << a
            << ", inverse = " << inverse;
    }
}

TEST(HQCTest, GFGenerateTables) {
    uint16_t exp[258] = {};
    uint16_t log[256] = {};

    gf_generate(exp, log, PARAM_M);

    for (size_t i = 0; i < 258; ++i) {
        EXPECT_EQ(gf_exp[i], exp[i]) << "exp index = " << i;
    }

    for (size_t i = 0; i < 256; ++i) {
        EXPECT_EQ(gf_log[i], log[i]) << "log index = " << i;
    }
}

TEST(HQCTest, GFMod) {
    for (uint16_t i = 0; i < 2 * PARAM_GF_MUL_ORDER; ++i) {
        EXPECT_EQ(i % PARAM_GF_MUL_ORDER, gf_mod(i))
            << "i = " << i;
    }
}

TEST(HQCTest, GFTablesBijection) {
  // exp(log(a)) == a for all a in [1, 255]
  for (uint16_t a = 1; a < 256; ++a) {
    EXPECT_EQ(a, gf_exp[gf_log[a]]) << "a = " << a;
  }

  // log(exp(i)) == i for all i in [0, 254]
  for (uint16_t i = 0; i < 255; ++i) {
    EXPECT_EQ(i, gf_log[gf_exp[i]]) << "i = " << i;
  }
}

TEST(HQCTest, GFHighBitTruncation) {
  uint16_t a = 0x0105; // 5 with high byte set
  uint16_t b = 0x0203; // 3 with high byte set

  EXPECT_EQ(gf_mul(5, 3), gf_mul(a, b));
  EXPECT_EQ(gf_square(5), gf_square(a));
  EXPECT_EQ(gf_inverse(5), gf_inverse(a));
}

TEST(HQCTest, FFTZeroPolynomial) {
    uint16_t f[1 << PARAM_FFT] = {};
    uint16_t w[1 << PARAM_M] = {};

    fft(w, f, 1);

    for (size_t i = 0; i < (1U << PARAM_M); ++i) {
        EXPECT_EQ(0, w[i]) << "index = " << i;
    }
}

TEST(HQCTest, FFTConstantPolynomial) {
    uint16_t f[1 << PARAM_FFT] = {};
    uint16_t w[1 << PARAM_M] = {};

    f[0] = 0xA7;

    fft(w, f, 1);

    for (size_t i = 0; i < (1U << PARAM_M); ++i) {
        EXPECT_EQ(f[0], w[i]) << "index = " << i;
    }
}

TEST(HQCTest, FFTLinearPolynomial) {
    uint16_t f[1 << PARAM_FFT] = {};
    uint16_t w[1 << PARAM_M] = {};

    f[0] = 0x53;
    f[1] = 0xCA;

    fft(w, f, 2);

    for (size_t i = 0; i < (1U << PARAM_M); ++i) {
        uint16_t x = FFTPointForIndex(i);
        uint16_t expected = f[0] ^ gf_mul(f[1], x);

        EXPECT_EQ(expected, w[i]) << "index = " << i;
    }
}

TEST(HQCTest, FFTPolynomialEvaluation) {
    for (size_t coeff_count = 1;
         coeff_count <= (1U << PARAM_FFT);
         ++coeff_count) {

        uint16_t f[1 << PARAM_FFT] = {};

        for (size_t i = 0; i < coeff_count; ++i) {
            f[i] = (i * 73 + coeff_count * 29 + 0x5B) & 0xFF;
        }

        uint16_t w[1 << PARAM_M] = {};

        fft(w, f, coeff_count);

        for (size_t i = 0; i < (1U << PARAM_M); ++i) {
            uint16_t x = FFTPointForIndex(i);

            uint16_t expected = EvaluatePolynomial(
                f, coeff_count, x);

            ASSERT_EQ(expected, w[i])
                << "coeff_count = " << coeff_count
                << ", index = " << i
                << ", x = " << x;
        }
    }
}

TEST(HQCTest, FFTRetrieveErrorPolynomial) {
    const size_t size = 1U << PARAM_M;
    const size_t half = 1U << (PARAM_M - 1);

    for (size_t zero_index = 0; zero_index < size; ++zero_index) {
        uint16_t w[1 << PARAM_M];
        uint8_t error[1 << PARAM_M] = {};

        for (size_t i = 0; i < size; ++i) {
            w[i] = 1;
        }

        // Introduce exactly one zero evaluation.
        w[zero_index] = 0;

        fft_retrieve_error_poly(error, w);

        size_t expected_index;

        if (zero_index == 0 || zero_index == half) {
            expected_index = 0;
        } else {
            uint16_t x = FFTPointForIndex(zero_index);
            expected_index = PARAM_GF_MUL_ORDER - gf_log[x];
        }

        for (size_t i = 0; i < size; ++i) {
            EXPECT_EQ(i == expected_index ? 1 : 0, error[i])
                << "zero_index = " << zero_index
                << ", error_index = " << i;
        }
    }
}
TEST(HQCTest, FFTRetrieveMultipleErrors) {
    const size_t size = 1U << PARAM_M;
    uint16_t w[1 << PARAM_M];
    uint8_t error[1 << PARAM_M] = {};

    for (size_t i = 0; i < size; ++i) {
        w[i] = 1;
    }

    size_t zero1 = 5;
    size_t zero2 = 42;

    w[zero1] = 0;
    w[zero2] = 0;

    fft_retrieve_error_poly(error, w);

    uint16_t x1 = FFTPointForIndex(zero1);
    uint16_t x2 = FFTPointForIndex(zero2);

    size_t idx1 = PARAM_GF_MUL_ORDER - gf_log[x1];
    size_t idx2 = PARAM_GF_MUL_ORDER - gf_log[x2];

    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(i == idx1 || i == idx2 ? 1 : 0, error[i])
            << "error index = " << i;
    }
}
TEST(HQCTest, ReedSolomonNoErrors) {
    EXPECT_TRUE(TestReedSolomonCorrection(0));
}

TEST(HQCTest, ReedSolomonSingleError) {
    EXPECT_TRUE(TestReedSolomonCorrection(1));
}

TEST(HQCTest, ReedSolomonMaximumCorrectableErrors) {
    EXPECT_TRUE(TestReedSolomonCorrection(PARAM_DELTA));
}

TEST(HQCTest, ReedSolomonGeneratorPolyMatch) {
  uint16_t generated_poly[2 * PARAM_DELTA + 1] = {};
  bssl::compute_generator_poly(generated_poly);

  const uint16_t expected_poly[] = {RS_POLY_COEFS};
  const size_t poly_len = sizeof(expected_poly) / sizeof(expected_poly[0]);

  EXPECT_EQ(poly_len, static_cast<size_t>(2 * PARAM_DELTA + 1));
  EXPECT_EQ(0, memcmp(generated_poly, expected_poly, sizeof(expected_poly)));
}

TEST(HQCTest, ReedSolomonAllZeroes) {
  uint64_t msg[VEC_K_SIZE_64] = {};
  uint64_t cdw[VEC_N1_SIZE_64] = {};
  uint64_t decoded[VEC_K_SIZE_64] = {};

  bssl::reed_solomon_encode(cdw, msg);

  // Encoding an all-zero message must produce an all-zero codeword
  uint64_t zero_cdw[VEC_N1_SIZE_64] = {};
  EXPECT_EQ(0, memcmp(cdw, zero_cdw, sizeof(cdw)));

  bssl::reed_solomon_decode(decoded, cdw);
  EXPECT_EQ(0, memcmp(decoded, msg, sizeof(msg)));
}

TEST(HQCTest, ReedSolomonRandomizedTrials) {
  uint64_t state = UINT64_C(0x123456789abcdef0);

  for (size_t trial = 0; trial < 20; ++trial) {
    uint64_t msg[VEC_K_SIZE_64] = {};
    uint64_t cdw[VEC_N1_SIZE_64] = {};
    uint64_t corrupted[VEC_N1_SIZE_64] = {};
    uint64_t decoded[VEC_K_SIZE_64] = {};

    for (size_t i = 0; i < VEC_K_SIZE_64; ++i) {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      msg[i] = state;
    }

    bssl::reed_solomon_encode(cdw, msg);
    memcpy(corrupted, cdw, PARAM_N1);

    uint8_t *corrupted_bytes = reinterpret_cast<uint8_t *>(corrupted);
    for (size_t err = 0; err < PARAM_DELTA; ++err) {
      size_t pos = (err * 5 + trial) % PARAM_N1;
      corrupted_bytes[pos] ^= static_cast<uint8_t>((err + 1) * 19);
    }

    bssl::reed_solomon_decode(decoded, corrupted);
    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_K))
        << "Mismatch on trial " << trial;
  }
}

TEST(HQCTest, ReedMullerZeroMessage) {
    uint64_t msg[VEC_N1_SIZE_64] = {};
    uint64_t cdw[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_N1_SIZE_64] = {};

    reed_muller_encode(cdw, msg);

    uint64_t zero_cdw[VEC_N1N2_SIZE_64] = {};
    EXPECT_EQ(0, memcmp(cdw, zero_cdw, sizeof(cdw)));

    reed_muller_decode(decoded, cdw);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_N1));
}
TEST(HQCTest, ReedMullerEncodeDecode) {
    uint64_t msg[VEC_N1_SIZE_64] = {};
    uint64_t cdw[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_N1_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_N1; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(i * 37 + 0x5B);
    }

    reed_muller_encode(cdw, msg);
    reed_muller_decode(decoded, cdw);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_N1));
}
TEST(HQCTest, ReedMullerRepeatedCodewords) {
    uint64_t msg[VEC_N1_SIZE_64] = {};
    uint64_t cdw[VEC_N1N2_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_N1; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(i * 19 + 7);
    }

    reed_muller_encode(cdw, msg);

    const uint8_t *encoded = reinterpret_cast<const uint8_t *>(cdw);
    const size_t multiplicity = PARAM_N2 / 128;
    const size_t codeword_bytes = 16;

    for (size_t i = 0; i < PARAM_N1; ++i) {
        size_t base = i * multiplicity * codeword_bytes;

        for (size_t copy = 1; copy < multiplicity; ++copy) {
            EXPECT_EQ(0, memcmp(
                encoded + base,
                encoded + base + copy * codeword_bytes,
                codeword_bytes
            )) << "Message byte = " << i
              << ", copy = " << copy;
        }
    }
}

TEST(HQCTest, ReedMullerKnownEncoding) {
    uint64_t msg[VEC_N1_SIZE_64] = {};
    uint64_t cdw[VEC_N1N2_SIZE_64] = {};

    reinterpret_cast<uint8_t *>(msg)[0] = 0x01;

    reed_muller_encode(cdw, msg);

    uint8_t expected[VEC_N1N2_SIZE_BYTES] = {};

    memset(expected, 0xAA, (PARAM_N2 / 128) * 16);

    EXPECT_EQ(0, memcmp(cdw, expected, sizeof(expected)));
}

TEST(HQCTest, ReedMullerCorrectsBitErrors) {
    uint64_t msg[VEC_N1_SIZE_64] = {};
    uint64_t cdw[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_N1_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_N1; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(i * 31 + 0x42);
    }

    reed_muller_encode(cdw, msg);

    uint8_t *corrupted = reinterpret_cast<uint8_t *>(cdw);

    const size_t multiplicity = PARAM_N2 / 128;

    for (size_t i = 0; i < PARAM_N1; ++i) {
        size_t base = i * multiplicity * 16;

        for (size_t bit = 0; bit < 8; ++bit) {
            corrupted[base + bit] ^= 1;
        }
    }

    reed_muller_decode(decoded, cdw);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_N1));
}
TEST(HQCTest, ReedMullerExhaustiveAllBytes) {
  // Test every possible byte value (0 to 255) through RM(1,7) encode/decode
  for (uint16_t b = 0; b < 256; ++b) {
    uint64_t msg[VEC_N1_SIZE_64] = {};
    uint64_t cdw[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_N1_SIZE_64] = {};

    memset(msg, static_cast<uint8_t>(b), PARAM_N1);

    reed_muller_encode(cdw, msg);
    reed_muller_decode(decoded, cdw);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_N1)) << "Failed for byte 0x" << std::hex << b;
  }
}
TEST(HQCTest, ReedMullerMaximumCorrectableErrors) {
    uint64_t msg[VEC_N1_SIZE_64] = {};
    uint64_t cdw[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_N1_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_N1; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(
            (i % 2 == 0) ? (i * 13) : (i * 13 | 0x80));
    }

    reed_muller_encode(cdw, msg);

    uint8_t *corrupted = reinterpret_cast<uint8_t *>(cdw);

    const size_t multiplicity = PARAM_N2 / 128;
    const size_t codeword_bytes = multiplicity * 16;
    const size_t min_distance = multiplicity * 64;
    const size_t max_errors = (min_distance - 1) / 2;

    for (size_t i = 0; i < PARAM_N1; ++i) {
        size_t base = i * codeword_bytes;

        for (size_t err = 0; err < max_errors; ++err) {
            size_t bit_position = (err * 5 + 17) % PARAM_N2;

            corrupted[base + bit_position / 8] ^=
                static_cast<uint8_t>(1U << (bit_position % 8));
        }
    }

    reed_muller_decode(decoded, cdw);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_N1));
}
TEST(HQCTest, CodeZeroMessage) {
    uint64_t msg[VEC_K_SIZE_64] = {};
    uint64_t encoded[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_K_SIZE_64] = {};

    code_encode(encoded, msg);
    code_decode(decoded, encoded);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_K));
}
TEST(HQCTest, CodeEncodeDecode) {
    uint64_t msg[VEC_K_SIZE_64] = {};
    uint64_t encoded[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_K_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_K; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(i * 37 + 0x5B);
    }

    code_encode(encoded, msg);
    code_decode(decoded, encoded);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_K));
}
TEST(HQCTest, CodeInnerErrorCorrection) {
    uint64_t msg[VEC_K_SIZE_64] = {};
    uint64_t encoded[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_K_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_K; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(i * 31 + 0x42);
    }

    code_encode(encoded, msg);

    uint8_t *corrupted = reinterpret_cast<uint8_t *>(encoded);

    const size_t block_bytes = PARAM_N2 / 8;
    const size_t multiplicity = PARAM_N2 / 128;
    const size_t min_distance = multiplicity * 64;
    const size_t max_errors = (min_distance - 1) / 2;

    for (size_t symbol = 0; symbol < PARAM_N1; ++symbol) {
        size_t base = symbol * block_bytes;

        for (size_t err = 0; err < max_errors; ++err) {
            size_t bit_position = (err * 5 + 17) % PARAM_N2;

            corrupted[base + bit_position / 8] ^=
                static_cast<uint8_t>(1U << (bit_position % 8));
        }
    }

    code_decode(decoded, encoded);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_K));
}
TEST(HQCTest, CodeOuterErrorCorrection) {
    uint64_t msg[VEC_K_SIZE_64] = {};
    uint64_t encoded[VEC_N1N2_SIZE_64] = {};
    uint64_t decoded[VEC_K_SIZE_64] = {};

    uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

    for (size_t i = 0; i < PARAM_K; ++i) {
        msg_bytes[i] = static_cast<uint8_t>(i * 23 + 0x71);
    }

    code_encode(encoded, msg);

    uint8_t *corrupted = reinterpret_cast<uint8_t *>(encoded);

    const size_t block_bytes = PARAM_N2 / 8;

    for (size_t symbol = 0; symbol < PARAM_DELTA; ++symbol) {
        size_t base = symbol * block_bytes;

        for (size_t i = 0; i < block_bytes; ++i) {
            corrupted[base + i] ^= 0xFF;
        }
    }

    code_decode(decoded, encoded);

    EXPECT_EQ(0, memcmp(decoded, msg, PARAM_K));
}
TEST(HQCTest, CodeRandomizedTrials) {
    uint64_t state = UINT64_C(0x123456789abcdef0);

    for (size_t trial = 0; trial < 20; ++trial) {
        uint64_t msg[VEC_K_SIZE_64] = {};
        uint64_t encoded[VEC_N1N2_SIZE_64] = {};
        uint64_t decoded[VEC_K_SIZE_64] = {};

        uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);

        for (size_t i = 0; i < PARAM_K; ++i) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;

            msg_bytes[i] = static_cast<uint8_t>(state);
        }

        code_encode(encoded, msg);
        code_decode(decoded, encoded);

        EXPECT_EQ(0, memcmp(decoded, msg, PARAM_K))
            << "Mismatch on trial " << trial;
    }
}
TEST(HQCTest, CodeCombinedInnerAndOuterErrorCorrection) {
  uint64_t msg[VEC_K_SIZE_64] = {};
  uint64_t encoded[VEC_N1N2_SIZE_64] = {};
  uint64_t decoded[VEC_K_SIZE_64] = {};

  uint8_t *msg_bytes = reinterpret_cast<uint8_t *>(msg);
  for (size_t i = 0; i < PARAM_K; ++i) {
    msg_bytes[i] = static_cast<uint8_t>(i * 17 + 0x2A);
  }

  code_encode(encoded, msg);

  uint8_t *corrupted = reinterpret_cast<uint8_t *>(encoded);
  const size_t block_bytes = PARAM_N2 / 8;
  const size_t multiplicity = PARAM_N2 / 128;
  const size_t max_rm_errors = (multiplicity * 64 - 1) / 2;

  // 1. Destroy PARAM_DELTA entire blocks (to be fixed by Reed-Solomon)
  for (size_t symbol = 0; symbol < PARAM_DELTA; ++symbol) {
    size_t base = symbol * block_bytes;
    for (size_t i = 0; i < block_bytes; ++i) {
      corrupted[base + i] ^= 0xFF;
    }
  }

  // 2. Add light, correctable bit errors to remaining blocks (to be fixed by Reed-Muller)
  for (size_t symbol = PARAM_DELTA; symbol < PARAM_N1; ++symbol) {
    size_t base = symbol * block_bytes;
    for (size_t err = 0; err < max_rm_errors; ++err) {
      size_t bit_pos = (err * 5 + 7) % PARAM_N2;
      corrupted[base + bit_pos / 8] ^= static_cast<uint8_t>(1U << (bit_pos % 8));
    }
  }

  code_decode(decoded, encoded);
  EXPECT_EQ(0, memcmp(decoded, msg, PARAM_K));
}
TEST(HQCTest, VectorSetRandomFixedWeight) {
    const uint16_t weights[] = {
        0, PARAM_OMEGA, PARAM_OMEGA_R
    };

    uint8_t seed[SEED_BYTES];

    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = static_cast<uint8_t>(i);
    }

    for (uint16_t requested_weight : weights) {
        shake_state state;
        uint64_t v[VEC_N_SIZE_64] = {};

        seedexpander_init(&state, seed, sizeof(seed));

        vect_set_random_fixed_weight(&state, v, requested_weight);

        size_t actual_weight = 0;

        for (size_t i = 0; i < VEC_N_SIZE_64; ++i) {
            uint64_t word = v[i];

            while (word != 0) {
                word &= word - 1;
                ++actual_weight;
            }
        }

        EXPECT_EQ(static_cast<size_t>(requested_weight), actual_weight);

        EXPECT_EQ(UINT64_C(0),
                  v[VEC_N_SIZE_64 - 1] &
                  ~static_cast<uint64_t>(RED_MASK));
    }
}
TEST(HQCTest, VectorSetRandomFixedWeightDeterministic) {
    uint8_t seed[SEED_BYTES];

    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = static_cast<uint8_t>(i + 17);
    }

    shake_state state1, state2;

    uint64_t v1[VEC_N_SIZE_64] = {};
    uint64_t v2[VEC_N_SIZE_64] = {};

    seedexpander_init(&state1, seed, sizeof(seed));
    seedexpander_init(&state2, seed, sizeof(seed));

    vect_set_random_fixed_weight(&state1, v1, PARAM_OMEGA);
    vect_set_random_fixed_weight(&state2, v2, PARAM_OMEGA);

    EXPECT_EQ(0, memcmp(v1, v2, sizeof(v1)));
}
TEST(HQCTest, VectorSetRandom) {
    uint8_t seed[SEED_BYTES];

    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = static_cast<uint8_t>(i + 31);
    }

    shake_state state;
    uint64_t v[VEC_N_SIZE_64] = {};

    seedexpander_init(&state, seed, sizeof(seed));

    vect_set_random(&state, v);

    uint64_t zero[VEC_N_SIZE_64] = {};

    EXPECT_NE(0, memcmp(v, zero, sizeof(v)));
    EXPECT_EQ(UINT64_C(0),
              v[VEC_N_SIZE_64 - 1] &
              ~static_cast<uint64_t>(RED_MASK));
}
TEST(HQCTest, VectorSetRandomDeterministic) {
    uint8_t seed[SEED_BYTES];

    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = static_cast<uint8_t>(i + 53);
    }

    shake_state state1, state2;

    uint64_t v1[VEC_N_SIZE_64] = {};
    uint64_t v2[VEC_N_SIZE_64] = {};

    seedexpander_init(&state1, seed, sizeof(seed));
    seedexpander_init(&state2, seed, sizeof(seed));

    vect_set_random(&state1, v1);
    vect_set_random(&state2, v2);

    EXPECT_EQ(0, memcmp(v1, v2, sizeof(v1)));
}
TEST(HQCTest, ParsingSecretKeyRoundTrip) {
    uint8_t sk_seed[SEED_BYTES];
    uint8_t pk[PUBLIC_KEY_BYTES] = {};
    uint8_t sk[SECRET_KEY_BYTES] = {};
    uint8_t parsed_pk[PUBLIC_KEY_BYTES] = {};

    for (size_t i = 0; i < SEED_BYTES; ++i) {
        sk_seed[i] = static_cast<uint8_t>(i * 13 + 7);
    }

    for (size_t i = 0; i < PUBLIC_KEY_BYTES; ++i) {
        pk[i] = static_cast<uint8_t>(i * 17 + 31);
    }

    hqc_secret_key_to_string(sk, sk_seed, pk);

    EXPECT_EQ(0, memcmp(sk, sk_seed, SEED_BYTES));
    EXPECT_EQ(0, memcmp(sk + SEED_BYTES, pk, PUBLIC_KEY_BYTES));

    uint64_t x[VEC_N_SIZE_64] = {};
    uint64_t y[VEC_N_SIZE_64] = {};

    hqc_secret_key_from_string(x, y, parsed_pk, sk);

    EXPECT_EQ(0, memcmp(parsed_pk, pk, PUBLIC_KEY_BYTES));

    // Independently reconstruct the expected secret vectors.
    shake_state state;
    uint64_t expected_x[VEC_N_SIZE_64] = {};
    uint64_t expected_y[VEC_N_SIZE_64] = {};

    seedexpander_init(&state, sk_seed, SEED_BYTES);

    vect_set_random_fixed_weight(&state, expected_x, PARAM_OMEGA);
    vect_set_random_fixed_weight(&state, expected_y, PARAM_OMEGA);

    EXPECT_EQ(0, memcmp(x, expected_x, sizeof(x)));
    EXPECT_EQ(0, memcmp(y, expected_y, sizeof(y)));
}
TEST(HQCTest, ParsingPublicKeyRoundTrip) {
    uint8_t pk_seed[SEED_BYTES];

    uint64_t s[VEC_N_SIZE_64] = {};
    uint64_t h[VEC_N_SIZE_64] = {};
    uint64_t parsed_s[VEC_N_SIZE_64] = {};
    uint64_t expected_h[VEC_N_SIZE_64] = {};

    uint8_t pk[PUBLIC_KEY_BYTES] = {};

    for (size_t i = 0; i < SEED_BYTES; ++i) {
        pk_seed[i] = static_cast<uint8_t>(i * 19 + 11);
    }

    uint8_t *s_bytes = reinterpret_cast<uint8_t *>(s);

    for (size_t i = 0; i < VEC_N_SIZE_BYTES; ++i) {
        s_bytes[i] = static_cast<uint8_t>(i * 23 + 5);
    }

    s[VEC_N_SIZE_64 - 1] &= RED_MASK;

    hqc_public_key_to_string(pk, pk_seed, s);

    EXPECT_EQ(0, memcmp(pk, pk_seed, SEED_BYTES));
    EXPECT_EQ(0, memcmp(pk + SEED_BYTES, s, VEC_N_SIZE_BYTES));

    hqc_public_key_from_string(h, parsed_s, pk);

    EXPECT_EQ(0, memcmp(parsed_s, s, VEC_N_SIZE_BYTES));

    shake_state state;

    seedexpander_init(&state, pk_seed, SEED_BYTES);
    vect_set_random(&state, expected_h);

    EXPECT_EQ(0, memcmp(h, expected_h, sizeof(h)));
}
TEST(HQCTest, ParsingCiphertextRoundTrip) {
    uint64_t u[VEC_N_SIZE_64] = {};
    uint64_t v[VEC_N1N2_SIZE_64] = {};

    uint64_t parsed_u[VEC_N_SIZE_64] = {};
    uint64_t parsed_v[VEC_N1N2_SIZE_64] = {};

    uint8_t d[SHAKE256_512_BYTES] = {};
    uint8_t parsed_d[SHAKE256_512_BYTES] = {};

    uint8_t ct[VEC_N_SIZE_BYTES +
               VEC_N1N2_SIZE_BYTES +
               SHAKE256_512_BYTES] = {};

    uint8_t ct_roundtrip[VEC_N_SIZE_BYTES +
                         VEC_N1N2_SIZE_BYTES +
                         SHAKE256_512_BYTES] = {};

    uint8_t *u_bytes = reinterpret_cast<uint8_t *>(u);
    uint8_t *v_bytes = reinterpret_cast<uint8_t *>(v);

    for (size_t i = 0; i < VEC_N_SIZE_BYTES; ++i) {
        u_bytes[i] = static_cast<uint8_t>(i * 7 + 13);
    }

    for (size_t i = 0; i < VEC_N1N2_SIZE_BYTES; ++i) {
        v_bytes[i] = static_cast<uint8_t>(i * 11 + 29);
    }

    for (size_t i = 0; i < sizeof(d); ++i) {
        d[i] = static_cast<uint8_t>(i * 17 + 41);
    }

    hqc_ciphertext_to_string(ct, u, v, d);

    // Verify the serialized layout.
    EXPECT_EQ(0, memcmp(ct, u, VEC_N_SIZE_BYTES));

    EXPECT_EQ(0, memcmp(
        ct + VEC_N_SIZE_BYTES,
        v,
        VEC_N1N2_SIZE_BYTES));

    EXPECT_EQ(0, memcmp(
        ct + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES,
        d,
        sizeof(d)));

    hqc_ciphertext_from_string(
        parsed_u, parsed_v, parsed_d, ct);

    EXPECT_EQ(0, memcmp(u, parsed_u, VEC_N_SIZE_BYTES));
    EXPECT_EQ(0, memcmp(v, parsed_v, VEC_N1N2_SIZE_BYTES));
    EXPECT_EQ(0, memcmp(d, parsed_d, sizeof(d)));

    hqc_ciphertext_to_string(
        ct_roundtrip, parsed_u, parsed_v, parsed_d);

    EXPECT_EQ(0, memcmp(ct, ct_roundtrip, sizeof(ct)));
}
}  // namespace bssl
