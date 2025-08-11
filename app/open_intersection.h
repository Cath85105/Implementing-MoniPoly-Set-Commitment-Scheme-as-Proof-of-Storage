#ifndef OPEN_INTERSECTION_H
#define OPEN_INTERSECTION_H

#include <vector>
#include <utility>
#include "monipoly.h"
#include "core.h"
#include "bls_BLS12381.h"
#include "big_B384_58.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"

using namespace std;
using namespace B384_58;
using namespace BLS12381;

std::pair<std::vector<B384_58::BIG*>, BLS12381::ECP> OpenIntersection(
    const std::vector<B384_58::BIG*>& A,
    const B384_58::BIG* o,
    const std::vector<B384_58::BIG*>& A_prime,
    int l,
    const std::vector<BLS12381::ECP>& a_list
);

#endif
