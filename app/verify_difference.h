#ifndef VERIFY_DIFFERENCE_H
#define VERIFY_DIFFERENCE_H

#include <vector>
#include <string>

#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "fp12_BLS12381.h" // For FP12
#include "big_B384_58.h"
#include "PublicKey.h"
#include "monipoly.h"

using namespace std;
using namespace core;
using namespace BLS12381;
using namespace B384_58;


bool VerifyDifference(
    const PublicKey& pk,
    const BLS12381::ECP& C,
    const std::vector<B384_58::BIG*>& d_coeffs_from_proof,
    const BLS12381::ECP& W,
    const std::vector<B384_58::BIG*>& r_coeffs
);

#endif