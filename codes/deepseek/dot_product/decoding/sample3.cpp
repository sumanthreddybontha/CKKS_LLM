#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_vector(const vector<double> &vec, size_t print_size = 4) {
    cout << "[";
    for (size_t i = 0; i < print_size; i++) {
        cout << vec[i] << (i != print_size - 1 ? ", " : " ...]\n");
    }
}

int main() {
    // Step 1: Context setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;  // Larger poly modulus for more slots
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 30, 50}));
    
    auto context = SEALContext::Create(parms);
    
    // Step 2: Key generation
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Step 3: Data preparation
    vector<double> matrix(100);
    for (int i = 0; i < 100; i++) {
        matrix[i] = static_cast<double>(rand()) / RAND_MAX;
    }
    
    vector<double> kernel = {0.5, 0, -0.5,
                             1.0, 0, -1.0,
                             0.5, 0, -0.5};
    
    // Step 4: Encode and encrypt
    double scale = pow(2.0, 40);
    Plaintext plain_matrix;
    encoder.encode(matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Step 5: Process multiple positions in parallel
    vector<Ciphertext> partial_results;
    
    for (int ki = 0; ki < 3; ki++) {
        for (int kj = 0; kj < 3; kj++) {
            // Create shifted versions of the matrix
            Ciphertext shifted_matrix;
            evaluator.rotate_vector(encrypted_matrix, ki * 10 + kj, gal_keys, shifted_matrix);
            
            // Multiply by kernel coefficient
            Plaintext kernel_pt;
            vector<double> kernel_vec(encoder.slot_count(), kernel[ki * 3 + kj]);
            encoder.encode(kernel_vec, scale, kernel_pt);
            
            evaluator.multiply_plain_inplace(shifted_matrix, kernel_pt);
            evaluator.relinearize_inplace(shifted_matrix, relin_keys);
            evaluator.rescale_to_next_inplace(shifted_matrix);
            
            partial_results.push_back(shifted_matrix);
        }
    }
    
    // Step 6: Sum all partial results
    Ciphertext final_result = partial_results[0];
    for (size_t i = 1; i < partial_results.size(); i++) {
        evaluator.add_inplace(final_result, partial_results[i]);
    }
    
    // Step 7: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(final_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    
    cout << "First few dot product results:" << endl;
    print_vector(result);
    
    return 0;
}