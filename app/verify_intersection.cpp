#include "verify_intersection.h"
#include "monipoly.h"
#include "mpencode.h"
#include "PublicKey.h"
#include "big_util.h"
#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include "pair_BLS12381.h"
#include <algorithm>
#include <iostream>
#include <vector>

using namespace std;
using namespace core;
using namespace BLS12381;
using namespace B384_58;


bool VerifyIntersection(
    const PublicKey& pk,
    const BLS12381::ECP& C,
    const std::vector<BIG*>& A_prime, // Set A'
    const std::vector<BIG*>& I,       // Claimed intersection I
    const BLS12381::ECP& W,           // Witness W
    int l              // Minimum required size of I (passed from OpenIntersection)
) {
    // Actual size of the intersection I (this is 'l' in the paper's product limits)
    size_t l_intersection_size = I.size();

    if (l_intersection_size < (size_t)l && l > 0) {
        // a basic sanity check
        cout << "VerifyIntersection: Intersection I is smaller than threshold l." << endl;
        return false;
    }
    if (I.empty() && l > 0 && l_intersection_size == 0) { // If I is empty but was expected not to be.
         cout << "VerifyIntersection: Intersection I is empty but threshold > 0." << endl;
        return false;
    }

    // 1. Encode coefficients
    std::vector<BIG*> coeffs_A_prime = MPEncode(A_prime);
    std::vector<BIG*> coeffs_I = MPEncode(I);
    std::vector<BIG*> A_prime_minus_I = set_difference(A_prime, I);
    std::vector<BIG*> coeffs_A_prime_minus_I = MPEncode(A_prime_minus_I);

    // --- LHS Calculation ---
    // LHS_G1 = C * (Π a_j^{coeffs_A_prime[j]})^{-1}
    // LHS_G2 = X_0

    ECP lhs_g1_arg;
    ECP_copy(&lhs_g1_arg, const_cast<ECP*>(&C)); // lhs_g1_arg = C

    ECP commit_A_prime_g1 = compute_g1_product_sum(pk.a_list, coeffs_A_prime);
    ECP_neg(&commit_A_prime_g1); // Inverse: -Commit_G1(A')
    ECP_add(&lhs_g1_arg, &commit_A_prime_g1); // lhs_g1_arg = C + (-Commit_G1(A'))

    if (pk.X_list.empty()) {
        std::cerr << "VerifyIntersection Error: pk.X_list is empty, cannot get X_0." << std::endl;
        return false;
    }
    ECP2 lhs_g2_arg; // This is X_0
    ECP2_copy(&lhs_g2_arg, const_cast<ECP2*>(&pk.X_list[0])); // Assuming X_0 is pk.X_list[0]

    FP12 pairing_lhs;
    PAIR_ate(&pairing_lhs, &lhs_g2_arg, &lhs_g1_arg);
    PAIR_fexp(&pairing_lhs);

    // --- RHS Calculation ---
    // RHS_G1 = W * (Π a_j^{coeffs_A_prime_minus_I[j]})^{-1}
    // RHS_G2 = Π X_j^{coeffs_I[j]}

    ECP rhs_g1_arg;
    ECP_copy(&rhs_g1_arg, const_cast<ECP*>(&W)); // rhs_g1_arg = W

    ECP commit_A_prime_minus_I_g1 = compute_g1_product_sum(pk.a_list, coeffs_A_prime_minus_I);
    ECP_neg(&commit_A_prime_minus_I_g1); // Inverse: -Commit_G1(A' - I)
    ECP_add(&rhs_g1_arg, &commit_A_prime_minus_I_g1); // rhs_g1_arg = W + (-Commit_G1(A' - I))

    ECP2 rhs_g2_arg = compute_g2_product_sum(pk.X_list, coeffs_I); // Commit_G2(I)

    FP12 pairing_rhs;
    PAIR_ate(&pairing_rhs, &rhs_g2_arg, &rhs_g1_arg);
    PAIR_fexp(&pairing_rhs);
    
    bool result = FP12_equals(&pairing_lhs, &pairing_rhs);
    if (!result) {
        std::cout << "❌ VerifyIntersection: Pairing LHS != Pairing RHS" << std::endl;
        // maybe can add more detailed debug prints here like:
        // print x-coords of lhs_g1_arg, rhs_g1_arg
        // print x.a-coords of lhs_g2_arg, rhs_g2_arg
    }
    return result;
    
}