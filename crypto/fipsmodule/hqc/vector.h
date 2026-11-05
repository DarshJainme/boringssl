#ifndef OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_VECTOR_H
#define OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_VECTOR_H

/**
 * @file vector.h
 * @brief Header file for vector.cpp
 */


#include "shake.h"
#include <stdint.h>

namespace bssl
{
    
    void vect_set_random_fixed_weight(shake_state *ctx, uint64_t *v, uint16_t weight);
    void vect_set_random(shake_state *ctx, uint64_t *v);
    void vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);
    uint8_t vect_compare(const uint8_t *v1, const uint8_t *v2, uint32_t size);
    void vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v, uint32_t size_v);
} // namespace bssl

#endif // OPENSSL_HEADER_HQC_VECTOR_H
