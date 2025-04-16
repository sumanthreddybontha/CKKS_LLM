#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void modulus_switching_matrix_multiplication() {
    // Extended modulus chain for more switching steps
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, 
        {50, 30, 30, 30, 50}  // Extra primes for switching
    ));
    
    SEALContext context(params);
    // print_parameters(context);
    
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
    
    // Prepare data
    vector<double> matrix(100);
    vector<double> kernel(9, 0.1);
    for (size_t i = 0; i < 100; i++) {
        matrix[i] = static_cast<double>(i % 10) / 10.0;
    }
    
    // Encode and encrypt
    double scale = pow(2.0, 30);
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);
    
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Get initial level
    size_t level = context.get_context_data(encrypted_matrix.parms_id())->chain_index();
    cout << "Initial level: " << level << endl;
    
    // First operation
    evaluator.multiply_plain_inplace(encrypted_matrix, plain_kernel);
    evaluator.rescale_to_next_inplace(encrypted_matrix);
    level = context.get_context_data(encrypted_matrix.parms_id())->chain_index();
    cout << "After multiply+rescale, level: " << level << endl;
    
    // Modulus switch (noise reduction)
    evaluator.mod_switch_to_next_inplace(encrypted_matrix);
    level = context.get_context_data(encrypted_matrix.parms_id())->chain_index();
    cout << "After mod switch, level: " << level << endl;
    
    // IMPORTANT: After modulus switching, we must also switch the plaintext
    evaluator.mod_switch_to_inplace(plain_kernel, encrypted_matrix.parms_id());
    
    // Second operation
    evaluator.multiply_plain_inplace(encrypted_matrix, plain_kernel);
    evaluator.rescale_to_next_inplace(encrypted_matrix);
    level = context.get_context_data(encrypted_matrix.parms_id())->chain_index();
    cout << "After second multiply+rescale, level: " << level << endl;
    
    // Final decryption
    Plaintext plain_result;
    decryptor.decrypt(encrypted_matrix, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    cout << "Final results (first 10 values): ";
    for (size_t i = 0; i < 10; i++) {
        cout << result[i] << " ";
    }
    cout << endl;
}

int main() {
    modulus_switching_matrix_multiplication();
    return 0;
}