#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

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
        matrix[i] = sin(static_cast<double>(i));
    }
    
    vector<double> kernel = {0.1, 0.2, 0.1,
                             0.2, 0.3, 0.2,
                             0.1, 0.2, 0.1};
    
    // Pad to fit in a single ciphertext
    vector<double> padded_matrix(encoder.slot_count(), 0.0);
    copy(matrix.begin(), matrix.end(), padded_matrix.begin());
    
    // Step 4: Encode and encrypt
    double scale = pow(2.0, 30);
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(padded_matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Pre-compute rotated versions of the kernel
    vector<Plaintext> rotated_kernels(9);
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            vector<double> rotated_kernel(encoder.slot_count(), 0.0);
            rotated_kernel[i * 10 + j] = kernel[i * 3 + j];
            encoder.encode(rotated_kernel, scale, rotated_kernels[i * 3 + j]);
        }
    }
    
    // Step 5: Compute dot products using rotations
    Ciphertext result;
    bool first = true;
    
    for (int i = 0; i < 9; i++) {
        Ciphertext temp;
        evaluator.rotate_vector(encrypted_matrix, i, gal_keys, temp);
        evaluator.multiply_plain_inplace(temp, rotated_kernels[i]);
        evaluator.relinearize_inplace(temp, relin_keys);
        evaluator.rescale_to_next_inplace(temp);
        
        if (first) {
            result = temp;
            first = false;
        } else {
            evaluator.add_inplace(result, temp);
        }
    }
    
    // Step 6: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> decoded_result;
    encoder.decode(plain_result, decoded_result);
    
    // Extract the 8x8 output (valid padding)
    cout << "Dot product results:" << endl;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            cout << decoded_result[i * 10 + j] << " ";
        }
        cout << endl;
    }
    
    return 0;
}