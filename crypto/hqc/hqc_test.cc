// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gtest/gtest.h>

#include "hqc.h"
#include "parameters.h"
#include "vector.h"

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
  uint64_t a[4] = {
      0x0123456789abcdefULL,
      0xfedcba9876543210ULL,
      0xaaaaaaaaaaaaaaaaULL,
      0x5555555555555555ULL,
  };

  uint64_t b[4] = {
      0xffff0000ffff0000ULL,
      0x0000ffff0000ffffULL,
      0x5555555555555555ULL,
      0xaaaaaaaaaaaaaaaaULL,
  };

  uint64_t out[4] = {};

  vect_add(out, a, b, 4);

  EXPECT_EQ(out[0], 0xfedc45677654cdefULL);
  EXPECT_EQ(out[1], 0xfedc45677654cdefULL);
  EXPECT_EQ(out[2], 0xffffffffffffffffULL);
  EXPECT_EQ(out[3], 0xffffffffffffffffULL);
}

TEST(HQCTest, VectorCompare) {
  uint8_t a[] = {1, 2, 3, 4, 5};
  uint8_t b[] = {1, 2, 3, 4, 5};
  uint8_t c[] = {1, 2, 3, 4, 6};
  uint8_t d[] = {1, 2, 3, 4, 4};

  EXPECT_EQ(vect_compare(a, b, sizeof(a)), 0);
  EXPECT_EQ(vect_compare(a, c, sizeof(a)), 1);
  EXPECT_EQ(vect_compare(a, d, sizeof(a)), 1);
}

TEST(HQCTest, VectorResize) {
  uint64_t input[VEC_N1N2_SIZE_64] = {};
  uint64_t output[VEC_N_SIZE_64] = {};

  input[0] = 0x0123456789abcdefULL;
  input[VEC_N1N2_SIZE_64 - 1] = 0x123456789abcdef0ULL;

  vect_resize(output, PARAM_N, input, PARAM_N1N2);

  EXPECT_EQ(output[0], input[0]);
  EXPECT_EQ(output[VEC_N1N2_SIZE_64 - 1],
            input[VEC_N1N2_SIZE_64 - 1]);

  uint64_t truncated[VEC_N1N2_SIZE_64] = {};

  vect_resize(truncated, PARAM_N1N2, output, PARAM_N);

  EXPECT_EQ(truncated[0], input[0]);
}

}  // namespace bssl
