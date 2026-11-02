#include "domains.h"
#include "shake.h"

namespace bssl {

void shake256_512_ds(shake_state *state, uint8_t *output,
                         const uint8_t *input, size_t inlen, uint8_t domain) {
  BORINGSSL_keccak_init(state, boringssl_shake256);

  BORINGSSL_keccak_absorb(state, input, inlen);
  BORINGSSL_keccak_absorb(state, &domain, 1);

  BORINGSSL_keccak_squeeze(state, output, 64);
}

void shake_prng_init(shake_state *state, uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen) {
  uint8_t domain = PRNG_DOMAIN;
  BORINGSSL_keccak_init(state, boringssl_shake256);
  BORINGSSL_keccak_absorb(state, entropy_input, enlen);
  BORINGSSL_keccak_absorb(state, personalization_string, perlen);
  BORINGSSL_keccak_absorb(state, &domain, 1);
}

void shake_prng(shake_state *state, uint8_t *output, uint32_t outlen) {
  BORINGSSL_keccak_squeeze(state, output, outlen);
}

void seedexpander_init(shake_state *state, const uint8_t *seed, uint32_t seedlen) {
  uint8_t domain = SEEDEXPANDER_DOMAIN;
  BORINGSSL_keccak_init(state, boringssl_shake256);
  BORINGSSL_keccak_absorb(state, seed, seedlen);
  BORINGSSL_keccak_absorb(state, &domain, 1);
}

void seedexpander(shake_state *state, uint8_t *output, uint32_t outlen) {
  const uint8_t bsize = sizeof(uint64_t);
  const uint8_t remainder = outlen % bsize;
  uint8_t tmp[sizeof(uint64_t)];
  BORINGSSL_keccak_squeeze(state, output, outlen - remainder);
  if (remainder != 0) {
    BORINGSSL_keccak_squeeze(state, tmp, bsize);
    output += outlen - remainder;
    for (size_t i = 0; i < remainder; i++) {
      output[i] = tmp[i];
    }
  }
}

}  // namespace bssl