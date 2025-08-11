#include "big_util.h"
#include <iostream>
#include <algorithm>
#include <vector>

#include "core.h"
#include "bls_BLS12381.h"
#include "big_B384_58.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"

using namespace std;
using namespace B384_58;
using namespace BLS12381;

ECP compute_g1_product_sum(const vector<ECP>& G_list, const vector<BIG*>& coeffs) {
    ECP result_point;
    ECP_inf(&result_point); // point at infinity (identity for addition)
    if (coeffs.empty()) return result_point; // Identity if no coeffs

    if (G_list.size() < coeffs.size()) {
         cerr << "Error: G_list size (" << G_list.size() << ") is less than coeffs size (" << coeffs.size() << ") in compute_g1_product_sum." << endl;
        ECP_inf(&result_point); // Return identity on error

        return result_point;
    }

    for (size_t i = 0; i < coeffs.size(); ++i) {
        ECP term;
        ECP_copy(&term, const_cast<ECP*>(&G_list[i])); // term = G_list[i]
        ECP_mul(&term, *coeffs[i]);                  // term = G_list[i] * coeffs[i]
        ECP_add(&result_point, &term);               // result_point += term
    }
    return result_point;
}

// For G2 elements
ECP2 compute_g2_product_sum(const vector<ECP2>& G2_list, const vector<BIG*>& coeffs) {
    ECP2 result_point;
    ECP2_inf(&result_point); // point at infinity
    if (coeffs.empty()) return result_point; // Identity if no coeffs

    if (G2_list.size() < coeffs.size()) {
        cerr << "Error: G2_list size (" << G2_list.size() << ") is less than coeffs size (" << coeffs.size() << ") in compute_g2_product_sum." << endl;
        ECP2_inf(&result_point); // Return identity on error

        return result_point;
    }

    for (size_t i = 0; i < coeffs.size(); ++i) {
        ECP2 term;
        ECP2_copy(&term, const_cast<ECP2*>(&G2_list[i])); // term = G2_list[i] 
        ECP2_mul(&term, *coeffs[i]);                   // term = G2_list[i] * coeffs[i]
        ECP2_add(&result_point, &term);                // result_point += term
    }
    return result_point;
}

/** ORIGINAL set_difference here!!!
vector<BIG*> set_difference(const vector<BIG*>& A, const vector<BIG*>& B) {
    vector<BIG*> result;
    std::cout << "--- Inside set_difference ---" << std::endl;
    for (BIG* a_val : A) { 
        bool found = false;
        std::cout << "  Checking a_val_ptr: "; BIG_output(*a_val); std::cout << " (Addr: " << (void*)a_val << ")" << std::endl;
        for (BIG* b_val : B) { 
            std::cout << "    Against b_val_ptr: "; BIG_output(*b_val); std::cout << " (Addr: " << (void*)b_val << ")" << std::endl;
            bool are_equal = BIG_equal(a_val, b_val); // Call your BIG_equal
            std::cout << "    BIG_equal result: " << (are_equal ? "true" : "false") << std::endl;
            if (are_equal) {
                found = true;
                break;
            }
        }
        if (!found){
            result.push_back(a_val);
            std::cout << "    -> Added to result." << std::endl;
        } else {
            std::cout << "    -> Found. Not added." << std::endl;
        }
    }
    std::cout << "--- Exiting set_difference ---" << std::endl;
    return result;
}
**/

// NEW set_difference
vector<BIG*> set_difference(const vector<BIG*>& A, const vector<BIG*>& B) {
    vector<BIG*> result;
    //std::cout << "--- Inside set_difference ---" << std::endl;
    for (BIG* a_val : A) {
        bool found = false;
        //std::cout << "    Checking a_val_ptr: "; BIG_output(*a_val); std::cout << " (Addr: " << (void*)a_val << ")" << std::endl;
        for (BIG* b_val : B) {
            //std::cout << "        Against b_val_ptr: "; BIG_output(*b_val); std::cout << " (Addr: " << (void*)b_val << ")" << std::endl;
            bool are_equal = BIG_equal(a_val, b_val);
            //std::cout << "        BIG_equal result: " << (are_equal ? "true" : "false") << std::endl;
            if (are_equal) {
                found = true;
                break;
            }
        }
        if (!found){
            // Deep copy the BIG* value
            BIG* new_big = (BIG*)malloc(sizeof(BIG));
            if (new_big == nullptr) {
                
                std::cerr << "ERROR: Malloc failed in set_difference for new_big." << std::endl;

                for (BIG* b : result) { free(b); } // Clean up what was already allocated
                result.clear();//clean up already allocated memory in 'result'
                return result;
            }
            BIG_copy(*new_big, *a_val); // Copy the content
            result.push_back(new_big);
            std::cout << "    -> Added to result (deep copy)." << std::endl;
        } else {
            std::cout << "    -> Found. Not added." << std::endl;
        }
    }
    //std::cout << "--- Exiting set_difference ---" << std::endl;
    return result;
}