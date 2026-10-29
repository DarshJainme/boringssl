/**
 * @file vector.cpp
 * @brief Implementation of vectors sampling and some utilities for the HQC scheme
 */

#include "parameters.h"
#include "vector.h"
#include <string.h>


namespace bssl
{
    /**
     * @brief Adds two vectors
     *
     * @param[out] o Pointer to an array that is the result
     * @param[in] v1 Pointer to an array that is the first vector
     * @param[in] v2 Pointer to an array that is the second vector
     * @param[in] size Integer that is the size of the vectors
     */
    void vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size) {
        for (uint32_t i = 0 ; i < size ; ++i) {
            o[i] = v1[i] ^ v2[i];
        }
    }



    /**
     * @brief Compares two vectors
     *
     * @param[in] v1 Pointer to an array that is first vector
     * @param[in] v2 Pointer to an array that is second vector
     * @param[in] size Integer that is the size of the vectors
     * @returns 0 if the vectors are equals and a negative/positive value otherwise
     */
    uint8_t vect_compare(const uint8_t *v1, const uint8_t *v2, uint32_t size) {
        uint64_t r = 0;

        for (size_t i = 0; i < size; i++) {
            r |= v1[i] ^ v2[i];
        }

        r = (~r + 1) >> 63;
        return (uint8_t) r;
    }



    /**
     * @brief Resize a vector so that it contains <b>size_o</b> bits
     *
     * @param[out] o Pointer to the output vector
     * @param[in] size_o Integer that is the size of the output vector in bits
     * @param[in] v Pointer to the input vector
     * @param[in] size_v Integer that is the size of the input vector in bits
     */
    void vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v, uint32_t size_v) {
        uint64_t mask = 0x7FFFFFFFFFFFFFFF;
        int8_t val = 0;
        if (size_o < size_v) {

            if (size_o % 64) {
                val = 64 - (size_o % 64);
            }

            memcpy(o, v, VEC_N1N2_SIZE_BYTES);

            for (int8_t i = 0 ; i < val ; ++i) {
                o[VEC_N1N2_SIZE_64 - 1] &= (mask >> i);
            }
        } else {
            memcpy(o, v, CEIL_DIVIDE(size_v, 8));
        }
    }
} // namespace bssl
