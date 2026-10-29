#ifndef OPENSSL_HEADER_HQC_VECTOR_H
#define OPENSSL_HEADER_HQC_VECTOR_H

/**
 * @file vector.h
 * @brief Header file for vector.cpp
 */


#include <stdint.h>

namespace bssl
{
    void vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);
    uint8_t vect_compare(const uint8_t *v1, const uint8_t *v2, uint32_t size);
    void vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v, uint32_t size_v);
} // namespace bssl

#endif // OPENSSL_HEADER_HQC_VECTOR_H
