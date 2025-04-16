#include <iostream>
#include <vector>
#include <iomanip>
#include <chrono>
#include <thread>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Helper function to print banner
void print_example_banner(const string& title) {
    cout << endl;
    cout << "=========================================" << endl;
    cout << "> " << title << endl;
    cout << "=========================================" << endl;
    cout << endl;
}

// Helper function to print parameters
void print_parameters(const SEALContext& context) {
    auto& context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  scheme: " << (context_data.parms().scheme() == scheme_type::bfv ? "BFV" : "CKKS") << endl;
    cout << "  poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  coeff_modulus size: ";
    cout << context_data.parms().coeff_modulus().size() << " (";
    
    auto coeff_modulus = context_data.parms().coeff_modulus();
    for (size_t i = 0; i < coeff_modulus.size(); i++) {
        cout << coeff_modulus[i].bit_count();
        if (i < coeff_modulus.size() - 1) {
            cout << " + ";
        }
    }
    cout << ") bits" << endl;
    cout << endl;
}

// Helper function to print modulus chain info
void print_modulus_chain_info(const SEALContext& context, const string& operation) {
    auto context_data = context.first_context_data();
    cout << "=== " << operation << " ===" << endl;
    
    size_t chain_index = 0;
    while (context_data) {
        auto& parms = context_data->parms();
        auto& coeff_modulus = parms.coeff_modulus();
        
        cout << "Level " << chain_index << ": ";
        cout << coeff_modulus.size() << " primes (";
        for (size_t i = 0; i < coeff_modulus.size(); i++) {
            cout << coeff_modulus[i].bit_count();
            if (i < coeff_modulus.size() - 1) {
                cout << " + ";
            }
        }
        cout << " bits)" << endl;
        
        context_data = context_data->next_context_data();
        chain_index++;
    }
    cout << endl;
}

// Helper function to print noise budget
void print_noise_budget(Decryptor& decryptor, const Ciphertext& ciphertext, const string& label) {
    cout << "Noise budget " << label << ": ";
    cout << decryptor.invariant_noise_budget(ciphertext) << " bits" << endl;
    cout << endl;
}

// Visual progress indicator
void visual_progress(const string& message, int duration_ms = 1000) {
    cout << message << " ";
    cout.flush();
    
    for (int i = 0; i < 5; ++i) {
        this_thread::sleep_for(chrono::milliseconds(duration_ms / 5));
        cout << ".";
        cout.flush();
    }
    cout << endl;
}

int main() {
    print_example_banner("BFV Demo with Modulus Switching");

    // Set up parameters for BFV
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;  // Reduced from 16384 for better performance
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Create a modulus chain
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    
    SEALContext context(parms);
    print_parameters(context);

    // Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Create encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Create encoder
    BatchEncoder encoder(context);
    
    // Prepare input data (integers for BFV)
    vector<uint64_t> input{1, 2, 3, 4, 5, 6, 7, 0};  // Last element 0 to match slot count
    Plaintext plain;
    encoder.encode(input, plain);
    
    // Encrypt
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    print_modulus_chain_info(context, "After encryption");
    print_noise_budget(decryptor, encrypted, "Initial encryption");
    
    // [Rest of your operations...]
    // Note: The full sequence of operations would go here, but I've shortened
    // this example to focus on the compilation issue

    return 0;
}