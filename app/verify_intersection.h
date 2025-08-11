#ifndef VERIFY_INTERSECTION_H
#define VERIFY_INTERSECTION_H

#include <algorithm>
#include <iostream>
#include <vector>
#include "core.h"
#include "bls_BLS12381.h"
#include "big_B384_58.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "PublicKey.h" 
#include "monipoly.h"

using namespace std;
using namespace core;
using namespace BLS12381;
using namespace B384_58;

bool VerifyIntersection(
    const PublicKey& pk,
    const BLS12381::ECP& C,
    const std::vector<B384_58::BIG*>& A_prime,
    const std::vector<B384_58::BIG*>& I,
    const BLS12381::ECP& W,
    int l
);


#endif


