#include <iostream>
#include <limits> 
#include <fstream>   
#include <sys/stat.h> 
#include <filesystem>

#include <vector>
#include "core.h"
#include "bls_BLS12381.h"
#include "pair_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include "randapi.h"


// headers for handle_ functions and MoniPoly functions
#include "main_2.h"
#include "monipoly.h"

// handle user interaction and call the core Setup function (MoniPoly function)
PublicKey RunInitialSystemSetup() {
    // --- Step 1: Handle User Input for 'n' ---
    int n = 0;
    while (true) {
        std::cout << "Enter the maximum number of attributes per commitment (n): ";
        std::cin >> n;

        // Input validation
        if (std::cin.fail() || n <= 1) {
            std::cout << "Invalid input. 'n' must be an integer greater than 1." << std::endl;
            std::cin.clear(); // Clear error flags
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard bad input
        } else {
            break; // Input is valid
        }
    }

    // --- Step 2: Initialize the RNG ---
    char raw[100];
    for (int i = 0; i < 100; i++) raw[i] = i;
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;
    CREATE_CSPRNG(&RNG, &RAW);
    std::cout << "RNG Initialized." << std::endl;

    // --- Step 3: Call Setup function ---
    std::cout << "Running system setup for n=" << n << "..." << std::endl;
    auto [pk, sk] = Setup(n, RNG); 

    // --- Step 4: DISCARD THE SECRET KEY ---
    // state this for clarity
    std::cout << "Setup complete. The secret key (sk) has been discarded. Public Key (pk) is returned." << std::endl;

    KILL_CSPRNG(&RNG);

    // --- Step 5: Return ONLY the public key for the rest of the functions ---
    return pk;
}


int main() {

    // --- THIS IS THE ONLY PART OF main() THAT WILL RUN ---
    //run_polynomial_division_test();

    //std::cout << "\nTest finished. Exiting program." << std::endl;
    //return 0; // The program stops here.

    
    // 1. Setup the system

    PublicKey global_pk = RunInitialSystemSetup();
    
    // 2. Define storage paths and ensure they exist
    const std::string provider_storage_path = "./storage/provider/";
    const std::string client_storage_path = "./storage/client/";

    try {
        std::filesystem::create_directories(provider_storage_path);
        std::filesystem::create_directories(client_storage_path);
        std::cout << "Client and Provider storage directories are ready." << std::endl;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Fatal Error: Could not create storage directories: " << e.what() << std::endl;
        return 1;
    }

    
    handle_client_commit(
        global_pk,
        client_storage_path,
        provider_storage_path
    );
    
    
    handle_provider_proof_generation(
        global_pk,
        provider_storage_path,
        client_storage_path
    );
    
    
    handle_verifier_check(global_pk);
    

    handle_provider_difference_proof(
        global_pk, 
        provider_storage_path,
        client_storage_path
    );
    

    handle_verifier_difference_check(global_pk);

    std::cout << "\nProgram finished." << std::endl;
    return 0;

}