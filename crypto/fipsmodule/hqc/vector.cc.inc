/**
 * @file vector.cpp
 * @brief Implementation of vectors sampling and some utilities for the HQC scheme
 */

#include "params.h"
#include "shake.h"
#include "vector.h"
#include <string.h>


namespace bssl
{
    /**
    * @brief Generates a vector of a given Hamming weight
    *
    * This function generates uniformly at random a binary vector
    * of Hamming weight equal to the parameter weight.
    *
    * @param[in] ctx Pointer to the context of the seed expander
    * @param[out] v Pointer to an array
    * @param[in] weight Integer that is the Hamming weight
    */
    void vect_set_random_fixed_weight(shake_state *ctx, uint64_t *v,
                                    uint16_t weight) {
        uint32_t support[PARAM_OMEGA_R] = {0};
        uint32_t index_tab[PARAM_OMEGA_R] = {0};
        uint64_t bit_tab[PARAM_OMEGA_R] = {0};

        size_t random_bytes_size = 3 * weight;
        uint8_t rand_bytes[3 * PARAM_OMEGA_R] = {0};
        uint8_t inc;
        size_t i, j;

        i = 0;
        j = random_bytes_size;

        while (i < weight) {
            do {
                if (j == random_bytes_size) {
                    seedexpander(ctx, rand_bytes, random_bytes_size);
                    j = 0;
                }

                support[i] = ((uint32_t)rand_bytes[j++]) << 16;
                support[i] |= ((uint32_t)rand_bytes[j++]) << 8;
                support[i] |= rand_bytes[j++];

            } while (support[i] >= UTILS_REJECTION_THRESHOLD);

            support[i] = support[i] % PARAM_N;

            inc = 1;
            for (size_t k = 0; k < i; k++) {
                if (support[k] == support[i]) {
                    inc = 0;
                }
            }

            i += inc;
        }

        for (size_t support_idx = 0; support_idx < weight; support_idx++) {
            index_tab[support_idx] = support[support_idx] >> 6;
            int32_t pos = support[support_idx] & 0x3f;
            bit_tab[support_idx] = ((uint64_t)1) << pos;
        }

        uint64_t val = 0;

        for (uint32_t word_idx = 0; word_idx < VEC_N_SIZE_64; word_idx++) {
            val = 0;

            for (uint32_t support_idx = 0; support_idx < weight; support_idx++) {
                uint32_t tmp = word_idx - index_tab[support_idx];
                int val1 = 1 ^ ((tmp | -tmp) >> 31);
                uint64_t mask = -val1;

                val |= (bit_tab[support_idx] & mask);
            }

            v[word_idx] |= val;
        }
    }
    /**
    * @brief Generates a random vector of dimension PARAM_N
    *
    * @param[out] v Pointer to an array
    * @param[in] ctx Pointer to the context of the seed expander
    */
    void vect_set_random(shake_state *ctx, uint64_t *v) {
        uint8_t rand_bytes[VEC_N_SIZE_BYTES] = {0};

        seedexpander(ctx, rand_bytes, VEC_N_SIZE_BYTES);

        memcpy(v, rand_bytes, VEC_N_SIZE_BYTES);
        v[VEC_N_SIZE_64 - 1] &= BITMASK(PARAM_N, 64);
    }
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
