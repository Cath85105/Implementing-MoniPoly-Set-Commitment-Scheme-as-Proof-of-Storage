#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include <vector>
#include "core.h"
#include "bls_BLS12381.h"
#include "big_B384_58.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"

using namespace std;
using namespace BLS12381;

struct PublicKey {
    vector<ECP> a_list;   //G1 elements
    vector<ECP2> X_list;  //G2 elements 
    ECP g1;
    ECP2 g2;

    // Explicitly declare the default constructor
    PublicKey() = default;

    // --- Custom Copy Constructor for Deep Copy ---
    PublicKey(const PublicKey& other) 
        : g1(other.g1), g2(other.g2) // ECP and ECP2 likely have their own copy constructors
    {
        // Deep copy a_list
        a_list.reserve(other.a_list.size()); // Reserve memory to prevent reallocations
        for (const auto& ecp_point : other.a_list) {
            BLS12381::ECP new_point;
            BLS12381::ECP_copy(&new_point, const_cast<BLS12381::ECP*>(&ecp_point)); // Use MIRACL's copy function
            a_list.push_back(new_point);
        }

        // Deep copy X_list
        X_list.reserve(other.X_list.size()); // Reserve memory
        for (const auto& ecp2_point : other.X_list) {
            BLS12381::ECP2 new_point;
            BLS12381::ECP2_copy(&new_point, const_cast<BLS12381::ECP2*>(&ecp2_point)); // Use MIRACL's copy function
            X_list.push_back(new_point);
        }
    }

    // --- Custom Assignment Operator for Deep Copy ---
    PublicKey& operator=(const PublicKey& other) {
        if (this == &other) { // Handle self-assignment
            return *this;
        }

        // Clear current contents
        a_list.clear();
        X_list.clear();

        // Copy scalar members
        g1 = other.g1;
        g2 = other.g2;

        // Deep copy a_list
        a_list.reserve(other.a_list.size());
        for (const auto& ecp_point : other.a_list) {
            BLS12381::ECP new_point;
            BLS12381::ECP_copy(&new_point, const_cast<BLS12381::ECP*>(&ecp_point));
            a_list.push_back(new_point);
        }

        // Deep copy X_list
        X_list.reserve(other.X_list.size());
        for (const auto& ecp2_point : other.X_list) {
            BLS12381::ECP2 new_point;
            BLS12381::ECP2_copy(&new_point, const_cast<BLS12381::ECP2*>(&ecp2_point));
            X_list.push_back(new_point);
        }

        return *this;
    }

};

#endif 
