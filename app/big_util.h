#ifndef BIG_UTIL_H
#define BIG_UTIL_H

#include <iostream>
#include <algorithm>
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

 inline bool BIG_equal(B384_58::BIG* a, B384_58::BIG* b){ 

    
    if (a == nullptr && b == nullptr) {
        return true; 
    }
    if (a == nullptr || b == nullptr) {
        return false; 
    }

    // +++ DEBUG PRINT +++
    //std::cout << "BIG_equal: Comparing A="; B384_58::BIG_output(*a);
    //std::cout << "  with B="; B384_58::BIG_output(*b);
    // might be useful if print the addresses of the pointers 'a' and 'b' as well
    // std::cout << " (Addr A: " << (void*)a << ", Addr B: " << (void*)b << ")";

    int comp_res = B384_58::BIG_comp(*a, *b); // Call BIG_comp only once
    //std::cout << "  BIG_comp result: " << comp_res << " (0 means equal)" << std::endl;
    // +++ END DEBUG PRINT +++

    return comp_res == 0; // Return based on the stored result
}

BLS12381::ECP compute_g1_product_sum(
    const std::vector<BLS12381::ECP>& G_list,
    const std::vector<B384_58::BIG*>& coeffs
);

BLS12381::ECP2 compute_g2_product_sum(
    const std::vector<BLS12381::ECP2>& G2_list,
    const std::vector<B384_58::BIG*>& coeffs
);

std::vector<B384_58::BIG*> set_difference(
    const std::vector<B384_58::BIG*>& A, // First set
    const std::vector<B384_58::BIG*>& B  // Set of elements to remove from A
);

#endif
