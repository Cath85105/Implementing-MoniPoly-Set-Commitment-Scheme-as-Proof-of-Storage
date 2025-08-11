#include "mpencode.h"
#include "monipoly.h"
#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include <vector>
#include <cstdlib>  // for malloc, free 
#include <iostream> 

using namespace std;
using namespace B384_58;
using namespace BLS12381;

vector<BIG*> MPEncode(const vector<BIG*>& set) {
   
    /** 
    // +++ DEBUG PRINT +++
    cout << "--- Inside MPEncode ---" << endl;
    cout << "Input 'set' contains " << set.size() << " elements:" << endl;
    for (size_t i = 0; i < set.size(); ++i) {
        if (set[i] != nullptr) {
            cout << "  set[" << i << "]: ";
            BIG_output(*set[i]); // Assuming BIG_output prints to cout
            cout << endl;
        } else {
            cout << "  set[" << i << "]: NULL" << endl;
        }
    }
    // +++ END OF DEBUG PRINT +++
    */

    vector<BIG*> coeffs;

    // Initialize f(x) = 1
    BIG* one = (BIG*)malloc(sizeof(BIG));
    BIG_one(*one);
    coeffs.push_back(one);

    // Use the curve order for mod reductions
    BIG p;
    BIG_rcopy(p, const_cast<chunk *>(CURVE_Order));

    for (BIG* m : set) {
        //std::cout << "MPEncode: TOP of loop, *m_from_input_set = "; BIG_output(*m); std::cout << std::endl;
        //if (*m == nullptr) continue; // Skip null pointers in input

        BIG m_current_val; // BIG is an array of chunks, it's stack allocated here.

        BIG_copy(m_current_val, *m); // Copy value from *m to m_current_val

        //std::cout << "MPEncode: After BIG_copy to m_current_val, *m_from_input_set = "; BIG_output(*m); std::cout << std::endl;
        //std::cout << "MPEncode: m_current_val = "; BIG_output(m_current_val); std::cout << std::endl;

        size_t deg = coeffs.size();
        vector<BIG*> new_coeffs(deg + 1);

        // Allocate and zero new coefficients
        for (size_t i = 0; i <= deg; i++) {
            new_coeffs[i] = (BIG*)malloc(sizeof(BIG));

            //if (!new_coeffs[i]) { /* handle error, free already alloc'd new_coeffs & old coeffs & 'one' */ return {}; }

            BIG_zero(*new_coeffs[i]);
        }

        /** 
         // +++ DEBUG PRINT 2 FOR ADDRESS+++
        std::cout << "MPEncode DEBUG: Address of *m_from_input_set: " << (void*)m << std::endl;
        // If BIG is typedef chunk BIGTYPE[NBIG], then *m_from_input_set is the array itself.
        // The pointer is m_from_input_set.
        for (size_t k_debug = 0; k_debug < new_coeffs.size(); ++k_debug) {
            std::cout << "MPEncode DEBUG: Address of new_coeffs[" << k_debug << "]: " << (void*)new_coeffs[k_debug] << std::endl;
        }
        // +++ END DEBUG PRINT 2 FOR ADDRESS+++
        */

        for (size_t i = 0; i < deg; i++) {
            if (coeffs[i] == nullptr) continue; // Skip if old coeff is null

            BIG temp_product;
            BIG_modmul(temp_product, *coeffs[i], m_current_val, p);

            //BIG negated_term;
            //BIG_copy(negated_term, p);         // negated_term = p
            //BIG_sub(negated_term, negated_term, temp_product); // negated_term = p - temp_product
            
            //BIG_add(*new_coeffs[i], *new_coeffs[i], negated_term);
            BIG_add(*new_coeffs[i], *new_coeffs[i], temp_product);
            BIG_mod(*new_coeffs[i], p);

            BIG_add(*new_coeffs[i + 1], *new_coeffs[i + 1], *coeffs[i]);
            BIG_mod(*new_coeffs[i + 1], p);
        }

        // Free previous coeffs
        for (BIG* c : coeffs) { if (c) free(c); }
        coeffs = new_coeffs;

        /** 
        // +++ DEBUG PRINT 3: Value of *m input pointer at END of its processing loop +++
        std::cout << "MPEncode: End of loop for m_input_ptr = ";
        BIG_output(*m);
        std::cout << std::endl;
        // +++ END DEBUG PRINT 3 +++
        */
    }

    return coeffs;
}