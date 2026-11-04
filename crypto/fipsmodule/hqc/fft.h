#ifndef OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_FFT_H
#define OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_FFT_H

/**
 * @file fft.h
 * @brief Header file for fft.cc.inc
 */

#include <stddef.h>
#include <stdint.h>

namespace bssl {

void fft(uint16_t *w, const uint16_t *f, size_t f_coeffs);

void fft_retrieve_error_poly(uint8_t *error, const uint16_t *w);

}  // namespace bssl

#endif  // OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_FFT_H