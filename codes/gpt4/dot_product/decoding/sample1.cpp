#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

// Helper function to print parameters (optional)
void print_parameters(const SEALContext &context)
{
    auto &parms = context.key_context_data()->parms();
    cout << "/" << endl;
    cout << "| Encryption parameters :" << endl;
    cout << "|   scheme: CKKS" << endl;
    cout << "|   poly_modulus_degree: " << parms.poly_modulus_degree() << endl;
    cout << "|   coeff_modulus size: " 
         << context.key_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "\\" << endl;
}

int main() {
    // Step 1: Set up CKKS parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Create SEALContext (updated for older versions)
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Step 3: Key Generation (updated API)
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Create Galois keys for rotations: in older versions use create_galois_keys()
    vector<int> steps;
    for (int i = 0; i < 100; i++) {
        steps.push_back(i);
    }
    GaloisKeys gal_keys;
    keygen.create_galois_keys(steps, gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 4: Create matrix and kernel
    const size_t rows = 10, cols = 10, kernel_size = 3;
    double scale = pow(2.0, 40);

    // Create a 10x10 matrix filled with 1.0s and a 3x3 kernel filled with 0.5s
    vector<double> matrix(rows * cols, 1.0);
    vector<double> kernel(kernel_size * kernel_size, 0.5);

    // Step 5: Encode and Encrypt matrix and kernel
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);

    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Step 6: Perform the homomorphic dot product using a sliding window approach
    // (Only 8x8 outputs due to a 3x3 kernel sliding on a 10x10 input)
    vector<Ciphertext> dot_products;
    for (int i = 0; i <= rows - kernel_size; ++i) {
        for (int j = 0; j <= cols - kernel_size; ++j) {
            Ciphertext result;
            bool first = true;

            // For each kernel element, rotate, multiply, and add the result.
            for (int ki = 0; ki < kernel_size; ++ki) {
                for (int kj = 0; kj < kernel_size; ++kj) {
                    // Calculate shift: this simulates accessing the (i+ki, j+kj) element.
                    int shift = (i + ki) * cols + (j + kj);
                    Ciphertext rotated;
                    evaluator.rotate_vector(encrypted_matrix, shift, gal_keys, rotated);

                    // Encode the corresponding kernel value 
                    Plaintext plain_weight;
                    encoder.encode(kernel[ki * kernel_size + kj], scale, plain_weight);

                    // Multiply the rotated ciphertext with the kernel weight and rescale
                    evaluator.multiply_plain_inplace(rotated, plain_weight);
                    evaluator.rescale_to_next_inplace(rotated);

                    // Sum the partial dot-product results
                    if (first) {
                        result = rotated;
                        first = false;
                    } else {
                        // Align the modulus chain of "result" to that of "rotated"
                        evaluator.mod_switch_to_inplace(result, rotated.parms_id());
                        evaluator.add_inplace(result, rotated);
                    }
                }
            }
            dot_products.push_back(result);
        }
    }

    // Step 7: Decrypt and decode the first result of the convolution
    Plaintext result_plain;
    vector<double> result_values;
    decryptor.decrypt(dot_products[0], result_plain);
    encoder.decode(result_plain, result_values);

    cout << "First 3x3 Dot Product Result: " << result_values[0] << endl;
    return 0;
}