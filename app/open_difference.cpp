#include "open_difference.h"
#include "mpencode.h"         
#include "big_util.h"
#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h" //Curve_order
#include "pair_BLS12381.h"
#include <iostream>          
#include <vector>
#include <algorithm> 

// Helper function to free vector of BIG* 
void free_big_vector(std::vector<B384_58::BIG*>& vec) {
    for (B384_58::BIG* b : vec) {
        if (b) free(b);
    }
    vec.clear(); 
}


std::tuple<BLS12381::ECP, std::vector<B384_58::BIG*>, std::vector<B384_58::BIG*>, std::string>
OpenDifference(
    const PublicKey& pk,
    const std::vector<B384_58::BIG*>& A_private_attrs,
    const B384_58::BIG* o_monipoly_opening,
    const std::vector<B384_58::BIG*>& D_set_chosen_by_prover
) {
    // --- Setup for Error Returns ---
    ECP W_identity; ECP_inf(&W_identity);
    std::vector<B384_58::BIG*> empty_vec1;
    std::vector<B384_58::BIG*> empty_vec2;

    if (D_set_chosen_by_prover.empty()) {
        return std::make_tuple(W_identity, std::move(empty_vec1), std::move(empty_vec2), "OpenDifference Error: D_set cannot be empty.");
    }
    if (o_monipoly_opening == nullptr) {
        return std::make_tuple(W_identity, std::move(empty_vec1), std::move(empty_vec2), "OpenDifference Error: Monipoly opening 'o' is null.");
    }

    // Disjointness check
    for (BIG* d_val : D_set_chosen_by_prover) {
        for (BIG* a_val : A_private_attrs) {
            if (BIG_equal(d_val, a_val)) {
                return std::make_tuple(W_identity, std::move(empty_vec1), std::move(empty_vec2), "OpenDifference Error: D_set is not disjoint from A.");
            }
        }
    }

    // 1. Get Polynomial for f(x') from A U o
    std::vector<B384_58::BIG*> f_poly_set = A_private_attrs;
    f_poly_set.push_back(const_cast<B384_58::BIG*>(o_monipoly_opening));
    std::vector<B384_58::BIG*> f_coeffs = MPEncode(f_poly_set);

    // 2. Get Polynomial for d(x') from D_set
    std::vector<B384_58::BIG*> d_coeffs = MPEncode(D_set_chosen_by_prover);

    // Error checking for polynomial generation
    std::string error_msg = "";
    if (f_coeffs.empty() && !f_poly_set.empty()) error_msg = "MPEncode failed for f(x').";
    else if (d_coeffs.empty() && !D_set_chosen_by_prover.empty()) error_msg = "MPEncode failed for d(x').";
    else if (!d_coeffs.empty() && d_coeffs.size()==1 && BIG_iszilch(*d_coeffs[0])) error_msg = "d(x') is zero polynomial.";
    
    if (!error_msg.empty()){
        std::cerr << "OpenDifference Error: " << error_msg << std::endl;
        free_big_vector(f_coeffs);
        free_big_vector(d_coeffs);
        // CORRECTED: Return tuple matches signature.
        return std::make_tuple(W_identity, std::move(empty_vec1), std::move(empty_vec2), "OpenDifference Error: " + error_msg);
    }

    // 3. Perform Polynomial Division
    B384_58::BIG modulus_p;
    BIG_rcopy(modulus_p, const_cast<chunk *>(CURVE_Order));
    PolynomialDivisionResult div_result = PolynomialLongDivision(f_coeffs, d_coeffs, modulus_p);

    free_big_vector(f_coeffs);

    if (!div_result.error_message.empty()){
        std::cerr << "OpenDifference Error during Polynomial Division: " << div_result.error_message << std::endl;
        free_big_vector(div_result.quotient_coeffs);
        free_big_vector(div_result.remainder_coeffs);
        free_big_vector(d_coeffs); 

        return std::make_tuple(W_identity, std::move(empty_vec1), std::move(empty_vec2), "OpenDifference Error: " + div_result.error_message);
    }

    if (div_result.remainder_is_identically_zero) {
        std::cerr << "OpenDifference Info: Polynomial division was exact (invalid proof)." << std::endl;
        free_big_vector(div_result.quotient_coeffs);
        free_big_vector(div_result.remainder_coeffs);
        free_big_vector(d_coeffs); 
        
        return std::make_tuple(W_identity, std::move(empty_vec1), std::move(empty_vec2), "OpenDifference: Division exact, r(x')=0.");
    }

    if (pk.a_list.size() < div_result.quotient_coeffs.size()) {
        std::cerr << "OpenDifference Error: pk.a_list too short for quotient commitment." << std::endl;
        free_big_vector(div_result.quotient_coeffs);
        free_big_vector(div_result.remainder_coeffs);
        free_big_vector(d_coeffs); 
        
        return std::make_tuple(W_identity, std::move(empty_vec1), std::move(empty_vec2), "OpenDifference Error: pk.a_list too short.");
    }

    ECP W_q_commitment = compute_g1_product_sum(pk.a_list, div_result.quotient_coeffs);
    free_big_vector(div_result.quotient_coeffs); // done with quotient, so free it

    // 6. vectors for return
    std::vector<B384_58::BIG*> remainder_coeffs_to_return = std::move(div_result.remainder_coeffs);
    std::vector<B384_58::BIG*> d_coeffs_to_return = std::move(d_coeffs);

    // 7. CORRECTED: Final successful return.
    return std::make_tuple(W_q_commitment, std::move(remainder_coeffs_to_return), std::move(d_coeffs_to_return), "");
}

/** --- PolynomialLongDivision - Simplified Version
// It should allocate new BIG* for output quotient and remainder coefficients.
PolynomialDivisionResult PolynomialLongDivision(
    const std::vector<B384_58::BIG*>& N_in,  // Numerator
    const std::vector<B384_58::BIG*>& D_in,  // Denominator
    const B384_58::BIG& modulus_p_const_ref // Modulus (passed by const ref)
) {
    
    PolynomialDivisionResult result;
    std::cout << "POLYNOMIALLONGDIVISION --- RUNNING SIMPLIFIED STUB ---" << std::endl;

    // Create dummy quotient (e.g., Q(x) = 1)
    result.quotient_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
    BIG_one(*result.quotient_coeffs[0]);

    // Create dummy non-zero remainder (e.g., R(x) = 1)
    result.remainder_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
    BIG_one(*result.remainder_coeffs[0]);
    result.remainder_is_identically_zero = false; 
    result.error_message = "";

    return result;

}
**/

/**PolynomialLongDivision _ Real Version */
PolynomialDivisionResult PolynomialLongDivision(
    const std::vector<B384_58::BIG*>& N_in,  // Numerator f(x') for A U o
    const std::vector<B384_58::BIG*>& D_in,  // Denominator d(x') for D
    const B384_58::BIG& modulus_p        // CURVE_Order
) {

    PolynomialDivisionResult result; // Constructor initialise remainder_is_identically_zero = true

    if (D_in.empty() || (D_in.size() == 1 && BIG_iszilch(*D_in[0]))) {
        result.error_message = "Polynomial division by zero polynomial.";
        return result; // remainder_is_identically_zero is true (error)
    }

    if (N_in.empty()) { // Division of 0 by D
        result.quotient_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
        BIG_zero(*result.quotient_coeffs.back()); // Quotient is 0
        result.remainder_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
        BIG_zero(*result.remainder_coeffs.back()); // Remainder is 0
        result.remainder_is_identically_zero = true;
        return result;
    }

    std::vector<BIG*> R_coeffs; // Remainder, initially Numerator
    for(BIG* n_coeff : N_in) {
        BIG* r_coeff = (BIG*)malloc(sizeof(BIG));
        BIG_copy(*r_coeff, *n_coeff);
        R_coeffs.push_back(r_coeff);
    }

    int deg_N = N_in.size() - 1;
    int deg_D = D_in.size() - 1;

    if (deg_N < deg_D) { // If degree of Numerator < degree of Denominator
        result.quotient_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
        BIG_zero(*result.quotient_coeffs.back()); // Quotient is 0
        result.remainder_coeffs = R_coeffs;       // Remainder is Numerator itself
                                                  // R_coeffs ownership is transferred to result.
        R_coeffs.clear(); 

        
        // Check if remainder (N_in) is zero
        bool N_is_zero = true;
        for(BIG* n_coeff : N_in) { if(!BIG_iszilch(*n_coeff)) { N_is_zero = false; break; } }

        result.remainder_is_identically_zero = N_is_zero;
        return result;
    }

    // Initialize Quotient Q with zeros, degree of Q = deg_N - deg_D
    int deg_Q = deg_N - deg_D;

    for (int i = 0; i <= deg_Q; ++i) {
        result.quotient_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
        BIG_zero(*result.quotient_coeffs.back());
    }

    BIG lead_D_inv;
    BIG_invmodp(lead_D_inv, *D_in.back(), const_cast<chunk*>(modulus_p)); // (leading coeff of D)^-1

    // Main division loop (from highest degree of R down)
    for (int k = deg_N; k >= deg_D; --k) {
        if (R_coeffs.empty() || (size_t)(k - deg_D) >= result.quotient_coeffs.size() || (size_t)k >= R_coeffs.size() || R_coeffs[k] == nullptr) {
            break;
        }

        BIG* R_k = R_coeffs[k]; // leading term of current Remainder R_coeffs at iteration for x^k

        BIG term_coeff; // This is Q_coeffs[k - deg_D]
        BIG_modmul(term_coeff, *R_k, lead_D_inv, const_cast<chunk*>(modulus_p)); // term_coeff = R_k * lead_D_inv

        // Add to quotient: Q[k - deg_D] = term_coeff
        // (Note: BIG_add adds, so if Q was 0, it becomes term_coeff)
        BIG_add(*result.quotient_coeffs[k - deg_D], *result.quotient_coeffs[k - deg_D], term_coeff);
        BIG_mod(*result.quotient_coeffs[k - deg_D], const_cast<chunk*>(modulus_p));

        // Subtract term_coeff * x^(k-deg_D) * D(x) from R(x)

        for (int i = 0; i <= deg_D; ++i) {

            if (D_in[i] == nullptr || (size_t)(k - deg_D + i) >= R_coeffs.size() || R_coeffs[k-deg_D+i] == nullptr ) continue;

            BIG to_subtract_from_R_coeff; // term_coeff * D_in[i]

            BIG_modmul(to_subtract_from_R_coeff, term_coeff, *D_in[i], const_cast<chunk*>(modulus_p));
            BIG_sub(*R_coeffs[k - deg_D + i], *R_coeffs[k - deg_D + i], to_subtract_from_R_coeff);
            //New
            BIG_add(*R_coeffs[k - deg_D + i], *R_coeffs[k - deg_D + i], const_cast<chunk*>(modulus_p)); // Add this line
            //New: End
            BIG_mod(*R_coeffs[k - deg_D + i], const_cast<chunk*>(modulus_p)); // Ensure positive result from mod
        }
    }
    // What is left in R_coeffs (up to degree deg_D - 1) is the remainder
    // Remove leading zeros from R_coeffs if any (from subtraction)

    while (R_coeffs.size() > 1 && BIG_iszilch(*R_coeffs.back())) {
        free(R_coeffs.back());
        R_coeffs.pop_back();
    }

    result.remainder_coeffs = R_coeffs; 

    R_coeffs.clear(); 

    // Check if remainder is identically zero
    result.remainder_is_identically_zero = true;

    if (result.remainder_coeffs.empty()){ // Should not happen, should have at least one 0 coeff
         result.remainder_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
         BIG_zero(*result.remainder_coeffs.back());
    }

    for (BIG* r_coeff : result.remainder_coeffs) {

        if (r_coeff == nullptr || !BIG_iszilch(*r_coeff)) {
            result.remainder_is_identically_zero = false;
            break;
        }

    }

    if (result.remainder_coeffs.empty() && result.remainder_is_identically_zero){
        // ensure if it's truly zero, has [0] coefficient
        result.remainder_coeffs.push_back((BIG*)malloc(sizeof(BIG)));
        BIG_zero(*result.remainder_coeffs.back());

    }

    return result;

}

