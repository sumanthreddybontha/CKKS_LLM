#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_parameters(const shared_ptr<SEALContext> &context) {
    auto &context_data = *context->first_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  scheme: CKKS" << endl;
    cout << "  poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  coeff_modulus size: ";
    cout << context_data.total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  scale: " << context_data.parms().coeff_modulus().back().value() << endl;
}

int main() {
    // Step 1: Set up CKKS parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Custom coefficient modulus for 3x3 kernel dot product with 10x10 matrix
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, 20, 30 }));
    
    // Create context
    auto context = SEALContext::Create(parms);
    print_parameters(context);
    
    // Step 2: Generate keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // CKKS encoder
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Step 3: Prepare the data
    // 10x10 matrix flattened to 100 elements
    vector<double> matrix(100, 0.0);
    for (int i = 0; i < 100; i++) {
        matrix[i] = static_cast<double>(i % 10);
    }
    
    // 3x3 kernel flattened to 9 elements
    vector<double> kernel = {1.0, 0.0, -1.0, 
                             2.0, 0.0, -2.0, 
                             1.0, 0.0, -1.0};
    
    // Step 4: Encode and encrypt
    double scale = pow(2.0, 20);
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);
    
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Step 5: Homomorphic dot product
    Plaintext plain_result;
    Ciphertext encrypted_result;
    
    // For each position in the output (8x8 for valid padding)
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            // Calculate the starting index for this convolution position
            size_t start_idx = i * 10 + j;
            
            // Create a mask to zero out non-relevant elements
            vector<double> mask(100, 0.0);
            for (int ki = 0; ki < 3; ki++) {
                for (int kj = 0; kj < 3; kj++) {
                    mask[start_idx + ki * 10 + kj] = 1.0;
                }
            }
            
            // Encode and multiply by mask
            Plaintext plain_mask;
            encoder.encode(mask, scale, plain_mask);
            Ciphertext masked_matrix;
            evaluator.multiply_plain(encrypted_matrix, plain_mask, masked_matrix);
            evaluator.relinearize_inplace(masked_matrix, relin_keys);
            evaluator.rescale_to_next_inplace(masked_matrix);
            
            // Compute dot product with kernel
            Plaintext plain_kernel_padded;
            vector<double> kernel_padded(100, 0.0);
            for (int ki = 0; ki < 3; ki++) {
                for (int kj = 0; kj < 3; kj++) {
                    kernel_padded[start_idx + ki * 10 + kj] = kernel[ki * 3 + kj];
                }
            }
            encoder.encode(kernel_padded, scale, plain_kernel_padded);
            
            Ciphertext dot_product;
            evaluator.multiply_plain(masked_matrix, plain_kernel_padded, dot_product);
            evaluator.relinearize_inplace(dot_product, relin_keys);
            evaluator.rescale_to_next_inplace(dot_product);
            
            // Sum all elements (dot product)
            Ciphertext sum_result;
            evaluator.sum_elements(dot_product, relin_keys, sum_result);
            
            // Decrypt and decode
            decryptor.decrypt(sum_result, plain_result);
            vector<double> result;
            encoder.decode(plain_result, result);
            
            cout << "Dot product at (" << i << "," << j << "): " << result[0] << endl;
        }
    }
    
    return 0;
}