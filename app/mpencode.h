#ifndef MPENCODE_H
#define MPENCODE_H

#include <vector>
#include "monipoly.h"
#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"

std::vector<B384_58::BIG*> MPEncode(const std::vector<B384_58::BIG*>& set);

#endif
