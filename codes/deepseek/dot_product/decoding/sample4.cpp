#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Parameter setup with larger poly modulus
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    
    auto context = SEALContext::Create(parms);
    
    // Step 2: Key generation with Galois keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys(30); // Generate more Galois keys
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Step 3: Data preparation - multiple matrices in parallel
    int num_matrices = slot_count / 100;
    cout << "Processing " << num_matrices << " matrices in parallel" << endl;
    
    vector<double> matrices(slot_count, 0.0);
    for (int m = 0; m < num_matrices; m++) {
        for (int i = 0; i < 100; i++) {
            matrices[m * 100 + i] = static_cast<double>(rand()) / RAND_MAX;
        }
    }
    
    vector<double> kernel = {0.25, 0.5, 0.25,
                             0.5,  1.0, 0.5,
                             0.25, 0.5, 0.25};
    
    // Step 4: Encode and encrypt
    double scale = pow(2.0, 40);
    Plaintext plain_matrices;
    encoder.encode(matrices, scale, plain_matrices);
    Ciphertext encrypted_matrices;
    encryptor.encrypt(plain_matrices, encrypted_matrices);
    
    // Step 5: Process all matrices in parallel
    Ciphertext result;
    bool first = true;
    
    for (int ki = 0; ki < 3; ki++) {
        for (int kj = 0; kj < 3; kj++) {
            // Rotate matrices
            Ciphertext rotated;
            evaluator.rotate_vector(encrypted_matrices, ki * 10 + kj, gal_keys, rotated);
            
            // Multiply by kernel coefficient
            Plaintext kernel_pt;
            vector<double> kernel_values(slot_count, kernel[ki * 3 + kj]);
            encoder.encode(kernel_values, scale, kernel_pt);
            
            evaluator.multiply_plain_inplace(rotated, kernel_pt);
            evaluator.relinearize_inplace(rotated, relin_keys);
            evaluator.rescale_to_next_inplace(rotated);
            
            if (first) {
                result = rotated;
                first = false;
            } else {
                evaluator.add_inplace(result, rotated);
            }
        }
    }
    
    // Step 6: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> decoded_result;
    encoder.decode(plain_result, decoded_result);
    
    // Print first matrix's results
    cout << "First matrix dot product results (8x8):" << endl;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            cout << decoded_result[i * 10 + j] << " ";
        }
        cout << endl;
    }
    
    return 0;
}