#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_parameters(shared_ptr<SEALContext> context) {
    auto &context_data = *context->key_context_data();
    cout << "/ Encryption parameters:" << endl;
    cout << "| scheme: CKKS" << endl;
    cout << "| poly_modulus_degree: " << 
        context_data.parms().poly_modulus_degree() << endl;
    cout << "| coeff_modulus size: " << 
        context_data.total_coeff_modulus_bit_count() << " bits" << endl;
    
    // Removed noise_standard_deviation as it's not directly accessible in this version
    cout << endl;
}

int main() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Custom coefficient modulus for CKKS - provides enough primes for several operations
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 60 }));
    
    SEALContext context(parms, true);
    // print_parameters(context);
    
    // Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Set up initial values
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    vector<double> input(slot_count, 1.05); // Start with 1.05 (5% growth)
    cout << "Input vector: " << input[0] << " (repeated " << slot_count << " times)" << endl;
    
    // Encode and encrypt
    Plaintext plain;
    encoder.encode(input, pow(2.0, 40), plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    
    // Loop parameters
    int max_iterations = 10;
    int threshold_budget = 10; // bits
    int iteration = 0;
    
    cout << endl << "Starting iterative improvement loop..." << endl;
    
    while (iteration < max_iterations) {
        // Check noise budget
        int noise_budget = decryptor.invariant_noise_budget(encrypted);
        cout << "Iteration: " << iteration << ", Noise budget: " << noise_budget << " bits";
        
        if (noise_budget < threshold_budget) {
            cout << " (below threshold, stopping)" << endl;
            break;
        }
        cout << endl;
        
        // Square the ciphertext (compound growth)
        evaluator.multiply_inplace(encrypted, encrypted);
        evaluator.relinearize_inplace(encrypted, relin_keys);
        
        // Rescale to manage noise growth
        evaluator.rescale_to_next_inplace(encrypted);
        
        iteration++;
    }
    
    // Decrypt and decode final result
    Plaintext plain_result;
    decryptor.decrypt(encrypted, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    
    cout << endl << "Final result after " << iteration << " iterations: " << result[0] << endl;
    cout << "Expected result (1.05^" << (1 << iteration) << "): " << pow(1.05, (1 << iteration)) << endl;
    
    return 0;
}