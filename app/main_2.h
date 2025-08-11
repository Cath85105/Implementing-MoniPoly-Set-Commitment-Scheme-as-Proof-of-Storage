#pragma once

#include <fstream>   
#include <sys/stat.h> 
#include <vector>
#include <iostream>


#include "monipoly.h" 
#include <map>
#include <string>

#include <sstream>   
#include <iomanip>   


using namespace std;
using namespace B384_58;
using namespace BLS12381;

//void run_polynomial_division_test();

struct ProviderData { 
    std::string stored_file_path; 
    BIG opening_value_o;
};


// Declaration for the functions in main_2.cpp

void handle_client_commit(
    const PublicKey& pk,
    const std::string& client_storage_path,
    const std::string& provider_storage_path
);


void handle_provider_proof_generation(
    const PublicKey& pk,
    const std::string& provider_storage_path,
    const string& client_storage_path
);


void handle_verifier_check(
    const PublicKey& pk
);


void handle_provider_difference_proof(
    const PublicKey& pk,
    const std::string& provider_storage_path,
    const string& client_storage_path
);

void handle_verifier_difference_check (
    const PublicKey& pk
);


void handle_verifier_difference_check(
    const PublicKey& pk
);

