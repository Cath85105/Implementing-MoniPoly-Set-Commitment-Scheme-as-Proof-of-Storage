#include "main_2.h"

#include <chrono>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <sys/stat.h>
#include <cstring>

using namespace std;
using namespace core;
using namespace B384_58; 
using namespace BLS12381; 


struct DifferenceProof {
    BLS12381::ECP W;
    std::vector<B384_58::BIG*> d_coeffs;
    std::vector<B384_58::BIG*> r_coeffs;
};

enum class ParseState {
    NONE,
    READING_WITNESS,
    READING_REMAINDERS
};


string bytes_to_hex_string(const unsigned char* bytes, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return ss.str();
}

string BIG_to_string(const BIG& num) {
    char byte_buffer[MODBYTES_B384_58];
    BIG temp_num;
    BIG_copy(temp_num, const_cast<BIG&>(num)); 

    // Pass the temporary copy to the function
    BIG_toBytes(byte_buffer, temp_num);
    
    return bytes_to_hex_string(reinterpret_cast<const unsigned char*>(byte_buffer), MODBYTES_B384_58);
}

/** 
void log_big_vector(const std::string& label, const std::vector<B384_58::BIG*>& vec) {
    std::cout << "  [DEBUG] " << label << " (" << vec.size() << " elements):" << std::endl;
    for (size_t i = 0; i < vec.size(); ++i) {
        std::cout << "    [" << i << "]: ";

        BIG_output(*vec[i]);

        std::cout << std::endl;
    }
}
*/

void free_big_vector_here(vector<BIG*>& vec) {
    for (BIG* b : vec) {
        if (b) free(b);
    }
    vec.clear();
}

// Helper to convert hex string back into a vector of raw bytes (for proof verification)
vector<unsigned char> hex_string_to_bytes(const string& hex) {
    vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string");
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper to convert a hex string back into an ECP point
ECP string_to_ecp(const string& hex_str) {
    ECP point;
    ECP_inf(&point); // Default to point at infinity

    try {
        vector<unsigned char> bytes = hex_string_to_bytes(hex_str);
        octet O = { (int)bytes.size(), (int)bytes.size(), (char*)bytes.data() };
        // Corrected logic: check if ECP_fromOctet returns 0 (failure)
        if (ECP_fromOctet(&point, &O) == 0) {
            cerr << "Warning: Failed to deserialize ECP from string." << endl;
            ECP_inf(&point); // Still set to infinity on failure
        }
    } catch (const std::invalid_argument& e) {
        cerr << "Warning: Invalid hex string provided for ECP deserialization." << endl;
    }
    return point;
}

// Helper to convert a hex string back into a BIG number.
BIG* string_to_big(const string& hex_str) {
    BIG* num = (BIG*)malloc(sizeof(BIG));
    if (num == nullptr) { return nullptr; }

    try {
        vector<unsigned char> bytes = hex_string_to_bytes(hex_str);
        BIG_fromBytes(*num, (char*)bytes.data());
    } catch (const std::invalid_argument& e) {
        cerr << "Warning: Invalid hex string provided for BIG deserialization." << endl;
        BIG_zero(*num);
    }
    return num;
}

string ecp_to_string(const ECP& point) { 
    char buffer[2 * MODBYTES_B384_58 + 1]; 
    octet O = {0, sizeof(buffer), buffer};
    ECP_toOctet(&O, const_cast<ECP*>(&point), true);
    return bytes_to_hex_string(reinterpret_cast<const unsigned char*>(O.val), O.len);
}


BIG* attribute_string_to_BIG(const string& attr_string) {
    // 1. Hash the input string 
    hash256 H;
    char hash_output[32];

    HASH256_init(&H);
    // Process each byte of the string
    for (char c : attr_string) {
        HASH256_process(&H, c);
    }
    HASH256_hash(&H, hash_output);

    // 2. Allocate memory for the BIG number
    BIG* attr_big = (BIG*)malloc(sizeof(BIG));
    if (attr_big == nullptr) {
        cerr << "Error: Failed to allocate memory for BIG attribute." << endl;
        return nullptr;
    }
    //std::cout << "  [Debug] Allocated BIG at address: " << attr_big << std::endl;

    // 3. Convert the hash bytes into a double-length BIG
    DBIG d_big;
    BIG_dfromBytesLen(d_big, hash_output, 32);
    
    // 4. Reduce the number modulo the group order 'p'
    BIG p_order;
    BIG_rcopy(p_order, CURVE_Order); 
    
    BIG_dmod(*attr_big, d_big, p_order);

    return attr_big;
}

void hex_to_oct(core::octet& oct, const std::string& hex_str) {
    //std::cout << "  [Debug] hex_to_oct: Input string length: " << hex_str.length() << std::endl;
    //std::cout << "  [Debug] hex_to_oct: Input hex string: " << hex_str << std::endl;

    /**    
    size_t len = hex_str.length();
    char* c_hex = new char[hex_str.length() + 1];
    strncpy(c_hex, hex_str.c_str(), len);
    c_hex[len] = '\0'; // Ensure null termination
    */ 

    // required size for the octet value (half of the string)
    int required_len = hex_str.length() / 2;

    if (oct.val != nullptr) {
        // Clear existing memory if necessary to prevent leaks
        core::OCT_clear(&oct);
    }

    // Allocate new memory for the octet's value
    oct.val = new char[required_len];
    oct.len = 0; // Reset length
    oct.max = required_len; // Set max capacity
    
    //std::cout << "  [Debug] hex_to_oct: Pre-allocated octet memory, calling OCT_fromHex with pre-sized octet..." << std::endl;
    core::OCT_fromHex(&oct, const_cast<char*>(hex_str.c_str()));
    //std::cout << "  [Debug] hex_to_oct: OCT_fromHex returned. oct.len: " << oct.len << std::endl;

}

/** 
void clear_octet(octet* oct) {
    if (oct->val != nullptr) {
        delete[] oct->val;
        oct->val = nullptr;
    }
}
*/

void handle_client_commit(
    const PublicKey& pk,
    const string& client_storage_path,
    const string& provider_storage_path
) {
    // 1. Get File Path from User
    cout << "Enter the full path to the file you want to commit: ";
    string file_path;
    getline(cin >> ws, file_path);

    if (!filesystem::exists(file_path)) {
        cerr << "Error: File does not exist at path: " << file_path << endl;
        return;
    }

    // 2. Extract Attributes
    cout << "Extracting attributes..." << endl;
    // hold ALL attributes for the final commitment
    vector<string> all_attribute_strings;
    // ONLY hold the attributes manually entered by the Client
    vector<string> manual_attribute_strings; 

    // --- Part 1: Get the file hash attribute ---
    ifstream content_stream(file_path, ios::binary);
    string file_content((istreambuf_iterator<char>(content_stream)), istreambuf_iterator<char>());
    
    hash256 file_H;
    char file_hash[32]; 
    HASH256_init(&file_H);
    for (char c : file_content) { HASH256_process(&file_H, c); }
    HASH256_hash(&file_H, file_hash);
    
    all_attribute_strings.push_back("sha256_hash=" + bytes_to_hex_string(reinterpret_cast<const unsigned char*>(file_hash), 32));


    // --- Part 2: Get manual attributes from the user ---
    cout << "Enter additional attributes (e.g., name=Alice), one per line. Type 'done' when finished:" << endl;
    string manual_attr_str;
    while (getline(cin >> ws, manual_attr_str) && manual_attr_str != "done") {
        all_attribute_strings.push_back(manual_attr_str);
        manual_attribute_strings.push_back(manual_attr_str); // This is the one we'll save to file
    }

    cout << "  Extracted " << all_attribute_strings.size() << " total attributes." << endl;

    // --- Convert ALL attributes for the commitment ---
    vector<BIG*> attrs_as_bigs;
    for (const auto& attr_str : all_attribute_strings) {
        attrs_as_bigs.push_back(attribute_string_to_BIG(attr_str));
    }

    // 4. Call CommitForAuditing Function
    cout << "Generating commitment..." << endl;


    ECP C = CommitForAuditing(attrs_as_bigs, pk.a_list);

    // --- ADD ERROR CHECK ---
    if (ECP_isinf(&C)) {
        cerr << "\n!! COMMITMENT FAILED !!" << endl;
        cerr << "This usually means 'n' was set too small for the number of attributes provided." << endl;
        // cleanup allocated memory before exiting
        for (BIG* attr : attrs_as_bigs) {
            if (attr) free(attr);
        }
        return; //stop 
    }
    // --- END ERROR CHECK ---

    string C_str = ecp_to_string(C);
    cout << "  Generated Commitment ID: " << C_str << endl;

    // 5. Write directly to the file system
    try {
        string dest_data_path = provider_storage_path + C_str + ".data";
        filesystem::copy(file_path, dest_data_path, filesystem::copy_options::overwrite_existing);

        string dest_ovalue_path = provider_storage_path + C_str + ".ovalue";
        ofstream o_stream(dest_ovalue_path);
        o_stream << "1";
        o_stream.close();
        cout << "  File and o-value 'uploaded' to: " << provider_storage_path << endl;

        string dest_manual_attrs_path = provider_storage_path + C_str + ".manual_attrs";
        ofstream attrs_stream(dest_manual_attrs_path);
        for (const auto& attr_str : manual_attribute_strings) { 
            attrs_stream << attr_str << endl;
        }
        attrs_stream.close();
        cout << "  Manual attributes uploaded to provider." << endl;

        filesystem::path original_path(file_path);
        string receipt_filename = client_storage_path + original_path.filename().string() + ".receipt";
        
        ofstream receipt_stream(receipt_filename);
        receipt_stream << C_str;
        receipt_stream.close();
        cout << "  Client 'receipt' saved to: " << client_storage_path << endl;

    } catch (const filesystem::filesystem_error& e) {
        cerr << "Error during file operation: " << e.what() << endl;
    }

    // 6. Cleanup allocated memory
    for (BIG* attr : attrs_as_bigs) {
        if (attr) free(attr);
    }
}

// --- Provider Generate Intersection Proof ---
void handle_provider_proof_generation(
    const PublicKey& pk,
    const std::string& provider_storage_path,
    const string& client_storage_path
) {
    // --- 1. Get the Commitment ID from the User ---
    cout << "\n--- Provider: Intersection Proof Generation ---" << endl;
    cout << "Enter the Commitment ID (the long hex string from the receipt): ";
    string C_str;
    cin >> C_str;

    // --- 2. Locate the Provider's Data Files ---
    string data_path = provider_storage_path + C_str + ".data";
    string ovalue_path = provider_storage_path + C_str + ".ovalue";

    if (!filesystem::exists(data_path) || !filesystem::exists(ovalue_path)) {
        cerr << "Error: No data found for this Commitment ID. Proof generation failed." << endl;
        return;
    }
    cout << "  Found data for the given commitment." << endl;

    // --- 3. Load the Provider's Stored Data ---

    // 3a. Re-extract the original full attribute from stored data file.
    cout << "  Re-extracting original attributes from stored data..." << endl;
    vector<string> reconstructed_attribute_strings;
    
    // Part 1: Get the file hash attribute
    ifstream content_stream(data_path, ios::binary);
    string file_content((istreambuf_iterator<char>(content_stream)), istreambuf_iterator<char>());
    hash256 file_H;
    char file_hash[32];
    HASH256_init(&file_H);
    for (char c : file_content) { HASH256_process(&file_H, c); }
    HASH256_hash(&file_H, file_hash);

    reconstructed_attribute_strings.push_back("sha256_hash=" + bytes_to_hex_string(reinterpret_cast<const unsigned char*>(file_hash), 32));

    // --- Read the stored manual attributes strings---
    string manual_attrs_path = provider_storage_path + C_str + ".manual_attrs";
    if (filesystem::exists(manual_attrs_path)) {
        ifstream manual_attrs_stream(manual_attrs_path);
        string line;
        while (getline(manual_attrs_stream, line)) {
            if (!line.empty()) {
                // --- FIX: Use the consistent variable name ---
                reconstructed_attribute_strings.push_back(line);
            }
        }
    }

    // Now convert the complete set of strings to BIGs
    vector<BIG*> original_A;
    for (const auto& attr_str : reconstructed_attribute_strings) {
        original_A.push_back(attribute_string_to_BIG(attr_str));
    }

    // 3b. Load the opening value o
    BIG o_from_storage;
    ifstream o_stream(ovalue_path);
    int o_val;
    o_stream >> o_val; 
    BIG_one(o_from_storage); //o is always 1

    // --- 4. Get the Query Set A' from the Client ---
    cout << "Enter the query attributes (e.g., sha256_hash=...), one per line. Type 'done' when finished:" << endl;
    vector<BIG*> query_A_prime;
    string query_attr_str;
    while (getline(cin >> ws, query_attr_str) && query_attr_str != "done") {
        query_A_prime.push_back(attribute_string_to_BIG(query_attr_str));
    }

    // --- Get the intersection threshold, l from Client ---
    cout << "Enter the minimum number of attributes that must match (l): ";
    int l; 
    cin >> l;

    // --- 5. Call the OpenIntersection ---
    cout << "  Generating intersection proof for at least " << l << " attribute(s)..." << endl;

    auto [intersection_set, witness_W] = OpenIntersection(original_A, &o_from_storage, query_A_prime, l, pk.a_list);

    // --- 6. Output and Save the Proof ---
    cout << "\n--- Proof Generated Successfully ---" << endl;
    cout << "Intersection Set (I):" << endl;
    for (BIG* val : intersection_set) {
        cout << "  "; BIG_output(*val); cout << endl;
    }
    cout << "Witness (W): " << ecp_to_string(witness_W) << endl;

    // Save the proof to a file
    string proof_filename = provider_storage_path + C_str + ".proof";
    ofstream proof_stream(proof_filename);

    proof_stream << "Witness:" << ecp_to_string(witness_W) << endl;
    proof_stream << "Intersection:" << endl;
    for (BIG* val : intersection_set) {
        char byte_buffer[MODBYTES_B384_58]; // BIG_to_hex
        BIG_toBytes(byte_buffer, *val);
        string hex_str = bytes_to_hex_string(reinterpret_cast<const unsigned char*>(byte_buffer), MODBYTES_B384_58);
        proof_stream << hex_str << endl;
    }
    proof_stream.close();
    cout << "Proof saved to: " << proof_filename << endl;

    try {
        // The client needs a place to store proofs it receives.
        // Let's create a subdirectory for clarity.
        string client_proofs_path = client_storage_path + "received_proofs/";
        filesystem::create_directories(client_proofs_path); // Create if it doesn't exist

        // Construct the destination path for the client
        filesystem::path proof_p(proof_filename);
        string client_dest_path = client_proofs_path + proof_p.filename().string();
        
        // Copy the file
        filesystem::copy_file(proof_filename, client_dest_path, filesystem::copy_options::overwrite_existing);
        
        cout << "Proof also delivered to client at: " << client_dest_path << endl;

    } catch (const filesystem::filesystem_error& e) {
        cerr << "Warning: Could not deliver proof to client's folder. " << e.what() << endl;
    }

    // --- 7. Cleanup ---
    for (BIG* attr : original_A) { if (attr) free(attr); }
    for (BIG* attr : query_A_prime) { if (attr) free(attr); }
}

// --- Client Verify Intersection Proof ---
void handle_verifier_check(const PublicKey& pk) {
    cout << "\n--- Client: Intersection Proof Verification ---" << endl;

    // --- 1. Get all necessary information ---
    cout << "Enter the Commitment ID (C) to verify against: ";
    string C_str;
    cin >> C_str;

    cout << "Enter the path to the proof file generated by the provider\n(e.g., ./storage/client/received_proofs/" << C_str << ".proof): ";
    string proof_path;
    cin >> proof_path;

    cout << "Enter the EXACT query attributes that were used to generate this proof (one per line, then 'done'):" << endl;
    vector<string> query_attribute_strings;
    string query_attr_str;
    while (getline(cin >> ws, query_attr_str) && query_attr_str != "done") {
        query_attribute_strings.push_back(query_attr_str);
    }

    cout << "Enter the minimum number of attributes (l) that were required: ";
    int l;
    cin >> l;

    // --- 2. Load and Parse the Proof File ---
    ifstream proof_stream(proof_path);
    if (!proof_stream.is_open()) {
        cerr << "Error: Could not open proof file." << endl;
        return;
    }
    
    string line;
    string witness_W_str;
    vector<string> intersection_I_strings;

    while (getline(proof_stream, line)) {
        if (line.rfind("Witness:", 0) == 0) {
            witness_W_str = line.substr(8); // Get the string after "Witness:"
        } else if (line == "Intersection:") {
            // The following lines will be intersection set
            while (getline(proof_stream, line) && !line.empty()) {
                intersection_I_strings.push_back(line);
            }
        }
    }
    cout << "  Proof file loaded and parsed." << endl;

    // --- NEW: Sanity Check ---
    if (intersection_I_strings.size() < (size_t)l) {
        cerr << "!! VERIFICATION PRE-CHECK FAILED !!" << endl;
        cerr << "  The proof's intersection set has " << intersection_I_strings.size() 
             << " elements, but the required threshold 'l' was " << l << "." << endl;
        return; // stop
    }
    cout << "  Pre-check passed: Intersection size is valid." << endl;
    // --- END: Sanity Check ---

    // --- 3. Convert All Strings ---
    
    ECP C = string_to_ecp(C_str); 
    ECP W = string_to_ecp(witness_W_str);

    vector<BIG*> A_prime;
    for (const auto& s : query_attribute_strings) { A_prime.push_back(attribute_string_to_BIG(s)); }

    vector<BIG*> I;
    for (const auto& s : intersection_I_strings) { I.push_back(string_to_big(s)); }

    // --- 4. Call the VerifyIntersection ---
    bool is_valid = VerifyIntersection(pk, C, A_prime, I, W, l);

    // --- 5. Report the Final Result ---
    if (is_valid) {
        cout << "\n✅✅✅  SUCCESS: Proof has been cryptographically verified! ✅✅✅" << endl;
    } else {
        cout << "\n❌❌❌  FAILURE: Proof is INVALID! The data may have been tampered with or the proof is forged. ❌❌❌" << endl;
    }

    // --- 6. Cleanup ---
    for (BIG* attr : A_prime) { if (attr) free(attr); }
    for (BIG* attr : I) { if (attr) free(attr); }
}

// --- Provider Generate Difference Proof ---
void handle_provider_difference_proof(
    const PublicKey& pk,
    const std::string& provider_storage_path,
    const string& client_storage_path
) {
   cout << "\n--- Provider: Difference Proof Generation ---" << endl;

    // 1. Get Commitment ID from user
    cout << "Enter the Commitment ID (C) to prove against: ";
    string C_str;
    cin >> C_str;

    // --- 2. Locate Data Files ---
    string data_path = provider_storage_path + C_str + ".data";
    string ovalue_path = provider_storage_path + C_str + ".ovalue";

    if (!filesystem::exists(data_path) || !filesystem::exists(ovalue_path)) {
        cerr << "Error: No data found for this Commitment ID. Proof generation failed." << endl;
        return;
    }
    cout << "  Found data for the given commitment." << endl;

    // --- 3. Load the Stored Data ---

    // 3a. Re-extract the original full attribute set 'A' from the stored data file.
    cout << "  Re-extracting original attributes from stored data..." << endl;
    vector<string> reconstructed_attribute_strings;
    
    // Part 1: Get the file hash attribute
    ifstream content_stream(data_path, ios::binary);
    string file_content((istreambuf_iterator<char>(content_stream)), istreambuf_iterator<char>());
    hash256 file_H;
    char file_hash[32];
    HASH256_init(&file_H);
    for (char c : file_content) { HASH256_process(&file_H, c); }
    HASH256_hash(&file_H, file_hash);

    reconstructed_attribute_strings.push_back("sha256_hash=" + bytes_to_hex_string(reinterpret_cast<const unsigned char*>(file_hash), 32));

    // --- Part 2: Read the stored manual attributes strings---
    string manual_attrs_path = provider_storage_path + C_str + ".manual_attrs";
    if (filesystem::exists(manual_attrs_path)) {
        ifstream manual_attrs_stream(manual_attrs_path);
        string line;
        while (getline(manual_attrs_stream, line)) {
            if (!line.empty()) {
                // --- FIX: Use the consistent variable name ---
                reconstructed_attribute_strings.push_back(line);
            }
        }
    }

    // Now convert the complete set of strings to BIGs
    vector<BIG*> original_A;
    for (const auto& attr_str : reconstructed_attribute_strings) {
        original_A.push_back(attribute_string_to_BIG(attr_str));
    }

    // 3b. Load the opening value 'o'
    BIG o_from_storage;
    ifstream o_stream(ovalue_path);
    int o_val;
    o_stream >> o_val; // Read "1" from the file
    BIG_one(o_from_storage); // o is always 1

    // 4. Get the D (difference set) from the client
    cout << "Enter the attributes for the Difference Set (D) that should NOT be in the commitment (one per line, then 'done'):" << endl;
    vector<BIG*> D_set;
    string d_attr_str;
    while (getline(cin >> ws, d_attr_str) && d_attr_str != "done") {
        D_set.push_back(attribute_string_to_BIG(d_attr_str));
    }

    // 5. Call the OpenDifference
    cout << "  Generating difference proof..." << endl;

    auto [witness_Wq, remainder_coeffs, d_coeffs, error_msg] = OpenDifference(pk, original_A, &o_from_storage, D_set);

    // 6. Handle the result
    if (!error_msg.empty()) {
        cerr << "!! PROOF GENERATION FAILED: " << error_msg << endl;
        // Cleanup memory
        for (auto p : original_A) free(p);
        for (auto p : D_set) free(p);
        return;
    }

    // 7. Output and save the proof
    cout << "\n--- Difference Proof Generated Successfully ---" << endl;
    cout << "Witness (Wq): " << ecp_to_string(witness_Wq) << endl;

    cout << "Difference Set (D) roots:" << endl;
    for (BIG* val : D_set) {
        cout << "  "; BIG_output(*val); cout << endl;
    }

    cout << "Remainder Coefficients {r_j}:" << endl;
    for (BIG* val : remainder_coeffs) {
        cout << "  "; BIG_output(*val); cout << endl;
    }

    // filename for difference proof 
    string proof_filename = provider_storage_path + C_str + ".diff.proof";

    // --- 8a. Save the proof to the provider's storage ---
    try {
        ofstream proof_stream(proof_filename);
        if (!proof_stream.is_open()) {
            throw runtime_error("Could not open proof file for writing.");
        }

        proof_stream << "[Witness_Wq]" << endl;
        proof_stream << ecp_to_string(witness_Wq) << endl;

        proof_stream << "[Remainder_Coeffs_r]" << endl;
        for (BIG* r_val : remainder_coeffs) {
            string hex_str = BIG_to_string(*r_val);
            proof_stream << hex_str << endl;
        }

        proof_stream << "D_COEFFS_HEX:" << endl;
        for (size_t i = 0; i < d_coeffs.size(); ++i) {
            //string hex_str = BIG_to_string(*(d_coeffs[i]));
            proof_stream << BIG_to_string(*(d_coeffs[i])) << (i == d_coeffs.size() - 1 ? "" : ",");
        }
        proof_stream << endl;
        proof_stream.close();
        cout << "\nProof saved to provider storage at: " << proof_filename << endl;

    } catch (const exception& e) {
        cerr << "Error saving difference proof: " << e.what() << endl;
        // Cleanup and exit if cannot save the proof
        free_big_vector_here(remainder_coeffs); 
        for (auto p : original_A) free(p);
        for (auto p : D_set) free(p);
        return;
    }

    // --- 8b. Copy the proof to client's storage ---
    try {
        string client_storage_path = "./storage/client/";
        string client_proofs_path = client_storage_path + "received_proofs/";
        filesystem::create_directories(client_proofs_path);

        filesystem::path proof_p(proof_filename);
        string client_dest_path = client_proofs_path + proof_p.filename().string();
        
        filesystem::copy_file(proof_filename, client_dest_path, filesystem::copy_options::overwrite_existing);
        
        cout << "Proof also delivered to client at: " << client_dest_path << endl;
    } catch (const filesystem::filesystem_error& e) {
        cerr << "Warning: Could not deliver proof to client's folder. " << e.what() << endl;
    }

    // Cleanup
    free_big_vector_here(remainder_coeffs); 
    free_big_vector_here(d_coeffs); // <--- ADD THIS CLEANUP
    for (auto p : original_A) free(p);
    for (auto p : D_set) free(p);
    for (auto p : d_coeffs) { free(p); }
}

// A helper function to parse the .diff.proof file
// This is the CORRECTED parser.
bool parse_diff_proof_file(const std::string& proof_path, DifferenceProof& proof) {
    std::ifstream infile(proof_path);
    if (!infile.is_open()) {
        std::cerr << "Error: Could not open proof file: " << proof_path << std::endl;
        return false;
    }

    std::string line;
    // Assuming ParseState is defined elsewhere
    enum class ParseState { NONE, READING_WITNESS, READING_REMAINDERS };
    ParseState state = ParseState::NONE;

    while (std::getline(infile, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        if (line.empty()) continue;

        if (line == "[Witness_Wq]") {
            state = ParseState::READING_WITNESS;
            continue;
        }
        if (line == "[Remainder_Coeffs_r]") {
            state = ParseState::READING_REMAINDERS;
            continue;
        }

        if (line.rfind("D_COEFFS_HEX:", 0) == 0) {
            if (!std::getline(infile, line)) { 
                std::cerr << "Error: Unexpected end of file after D_COEFFS_HEX header." << std::endl;		
                return false;
            }
            
            std::stringstream ss(line);
            std::string d_hex;
            while(std::getline(ss, d_hex, ',')) {
                // CORRECTED: Use your existing string_to_big function
                B384_58::BIG* coeff = string_to_big(d_hex);
                if (coeff == nullptr) { 
                    std::cerr << "Error parsing D coefficient from hex." << std::endl;
                    return false;
                }
                proof.d_coeffs.push_back(coeff);
            }
            state = ParseState::NONE;
            continue;
        }

        if (state == ParseState::READING_WITNESS) {
            // This part is for the ECP point and should be fine.
            octet temp_oct = {0, 0, NULL};
            hex_to_oct(temp_oct, line);
            ECP_fromOctet(&proof.W, &temp_oct);
            OCT_clear(&temp_oct);
            state = ParseState::NONE;
        } else if (state == ParseState::READING_REMAINDERS) {
            // CORRECTED: Use your existing string_to_big function
            B384_58::BIG* coeff = string_to_big(line);
            if (!coeff) { 
                std::cerr << "Error parsing R coefficient from hex." << std::endl;
                return false; 
            }
            proof.r_coeffs.push_back(coeff);
        }
    }
    
    // ... (the final check) ...
    if (proof.d_coeffs.empty() || proof.r_coeffs.empty() || BLS12381::ECP_isinf(&proof.W)) {
        std::cerr << "Error: Proof file was incomplete. Final check failed." << std::endl;
        std::cout << " [Debug] d_coeffs size: " << proof.d_coeffs.size() << std::endl;
        std::cout << " [Debug] r_coeffs size: " << proof.r_coeffs.size() << std::endl;
        std::cout << " [Debug] W is infinity: " << BLS12381::ECP_isinf(&proof.W) << std::endl;
        return false;
    }

    return true;
}


void handle_verifier_difference_check(const PublicKey& pk) {
    std::cout << "\n--- Client: Difference Proof Verification ---\n";

    // 1. Get inputs from user
    std::cout << "Enter the Commitment ID (hex) to verify against: ";
    std::string commit_id_hex;
    std::cin >> commit_id_hex;

    std::cout << "Enter the path to the difference proof file to verify\n(e.g., ./storage/client/received_proofs/" << commit_id_hex << ".diff.proof): ";
    std::string proof_path;
    std::cin >> proof_path;

    // --- 2. Convert Commitment ID  ---
    //std::cout << "  [Debug] Calling hex_to_oct for commitment ID..." << std::endl;
    ECP C;
    octet C_oct = {0, 0, NULL};
    hex_to_oct(C_oct, commit_id_hex);
    //std::cout << "  [Debug] Calling ECP_fromOctet..." << std::endl;
    if (!ECP_fromOctet(&C, &C_oct)) {
        std::cerr << "Error: Invalid Commitment ID format. Could not convert hex to ECP point." << std::endl;
        OCT_clear(&C_oct);
        return;
    }
    OCT_clear(&C_oct); // Clean up 
    std::cout << "  Commitment C successfully loaded from ID." << std::endl;

    // --- 3. Load and Parse the Proof File ---
    DifferenceProof proof;
    if (!parse_diff_proof_file(proof_path, proof)) {
        std::cerr << "Error: Failed to load or parse the proof file. Please check the path or file content." << std::endl;
        return;
    }
    //std::cout << "  Proof file loaded and parsed." << std::endl;

    // --- 4. Sanity Check ---
    if (proof.d_coeffs.empty() || proof.r_coeffs.empty()) {
         std::cerr << "!! VERIFICATION PRE-CHECK FAILED !!" << std::endl;
         std::cerr << "  The proof file is missing the Difference Set (D) or Remainder Coefficients (r)." << std::endl;
         return;
    }

    if ((proof.r_coeffs.size() + 1) != proof.d_coeffs.size()) {
         std::cerr << "!! VERIFICATION PRE-CHECK FAILED !!" << std::endl;
         std::cerr << "  Mismatch between size of difference set (" << proof.d_coeffs.size()
                   << ") and size of remainder coefficients (" << proof.r_coeffs.size() << ")." << std::endl;
         return;
    }
    //std::cout << "  Pre-check passed: Proof structure is valid." << std::endl;

    // --- 5. Call the VerifyDifference ---

    bool is_valid = VerifyDifference(pk, C, proof.d_coeffs, proof.W, proof.r_coeffs);

     // --- 6. Report the Final Result ---
    if (is_valid) {
        std::cout << "\n✅✅✅  SUCCESS: Proof has been cryptographically verified! ✅✅✅" << std::endl;
        std::cout << "  This confirms the specified attributes are NOT in the original commitment." << std::endl;
    } else {
        std::cout << "\n❌❌❌  FAILURE: Proof is INVALID! ❌❌❌" << std::endl;
        std::cout << "  The proof is forged or the data does not match the commitment." << std::endl;
    }

    //Cleanup
    std::cout << "  Cleaning up allocated memory..." << std::endl;
    for (B384_58::BIG* b : proof.d_coeffs) {
        if (b) free(b);
    }
    for (B384_58::BIG* b : proof.r_coeffs) {
        if (b) free(b);
    }

}


