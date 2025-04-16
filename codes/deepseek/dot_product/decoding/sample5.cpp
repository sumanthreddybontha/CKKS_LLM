#include <iostream>
#include <vector>
#include <seal/seal.h>
#include <cmath>

using namespace std;
using namespace seal;

vector<double> compute_plain_dot(const vector<double> &matrix, const vector<double> &kernel) {
    vector<double> result(64, 0.0); // 8x8 result
    
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            double sum = 0.0;
            for (int ki = 0; ki < 3; ki++) {
                for (int kj = 0; kj < 3; kj++) {
                    sum += matrix[(i + ki) * 10 + (j + kj)] * kernel[ki * 3 + kj];
                }
            }
            result[i * 8 + j] = sum;
        }
    }
    return result;
}

int main() {
    // Step 1: Parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 30, 40}));
    
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
        matrix[i] = static_cast<double>(i % 10) * 0.1;
    }
    
    vector<double> kernel = {0.1, 0.2, 0.1,
                             0.2, 0.4, 0.2,
                             0.1, 0.2, 0.1};
    
    // Compute plaintext result for validation
    auto plain_result = compute_plain_dot(matrix, kernel);
    
    // Step 4: Encode and encrypt
    double scale = pow(2.0, 30);
    Plaintext plain_matrix;
    encoder.encode(matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Step 5: Homomorphic convolution
    Ciphertext final_result;
    bool first = true;
    
    for (int ki = 0; ki < 3; ki++) {
        for (int kj = 0; kj < 3; kj++) {
            // Rotate matrix
            Ciphertext rotated;
            evaluator.rotate_vector(encrypted_matrix, ki * 10 + kj, gal_keys, rotated);
            
            // Multiply by kernel value
            Plaintext kernel_pt;
            vector<double> kernel_vec(encoder.slot_count(), kernel[ki * 3 + kj]);
            encoder.encode(kernel_vec, scale, kernel_pt);
            
            evaluator.multiply_plain_inplace(rotated, kernel_pt);
            evaluator.relinearize_inplace(rotated, relin_keys);
            evaluator.rescale_to_next_inplace(rotated);
            
            if (first) {
                final_result = rotated;
                first = false;
            } else {
                evaluator.add_inplace(final_result, rotated);
            }
        }
    }
    
    // Step 6: Decrypt and decode
    Plaintext pt_result;
    decryptor.decrypt(final_result, pt_result);
    vector<double> he_result;
    encoder.decode(pt_result, he_result);
    
    // Step 7: Validation
    double max_error = 0.0;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            double error = abs(he_result[i * 10 + j] - plain_result[i * 8 + j]);
            if (error > max_error) {
                max_error = error;
            }
        }
    }
    
    cout << "Maximum absolute error: " << max_error << endl;
    cout << "First few results (plain vs HE):" << endl;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            cout << "(" << i << "," << j << "): " 
                 << plain_result[i * 8 + j] << " vs " 
                 << he_result[i * 10 + j] << endl;
        }
    }
    
    return 0;
}