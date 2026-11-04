/**
 * \file gf2x.h
 * \brief Header file for gf2x.cc.inc
 */

#ifndef OPENSSL_HEADER_HQC_GF2X_H
#define OPENSSL_HEADER_HQC_GF2X_H

#include <stdint.h>

namespace bssl {

void vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2);

}  // namespace bssl

#endif
