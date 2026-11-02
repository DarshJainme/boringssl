#ifndef OPENSSL_HEADER_HQC_SHAKE_H
#define OPENSSL_HEADER_HQC_SHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "../keccak/internal.h"

namespace bssl {

using shake_state = BORINGSSL_keccak_st;

void shake256_512_ds(shake_state *state, uint8_t *output,const uint8_t *input, size_t inlen, uint8_t domain);

void shake_prng_init(shake_state *state, uint8_t *entropy_input,uint8_t *personalization_string, uint32_t enlen,uint32_t perlen);

void shake_prng(shake_state *state, uint8_t *output, uint32_t outlen);

void seedexpander_init(shake_state *state, const uint8_t *seed, uint32_t seedlen);

void seedexpander(shake_state *state, uint8_t *output, uint32_t outlen);

}  // namespace bssl

#endif