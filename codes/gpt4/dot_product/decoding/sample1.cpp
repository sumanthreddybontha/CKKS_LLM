#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up CKKS parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Create SEALContext
    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;

    // Step 3: Key Generation
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    auto gal_keys = keygen.galois_keys();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 4: Create matrix and kernel
    const size_t rows = 10, cols = 10, kernel_size = 3;
    double scale = pow(2.0, 40);

    vector<double> matrix(rows * cols, 1.0);
    vector<double> kernel(kernel_size * kernel_size, 0.5);

    // Step 5: Encode and Encrypt matrix
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);

    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Step 6: Perform homomorphic dot product using sliding window
    // Only 8x8 output due to 3x3 kernel sliding on 10x10 input
    vector<Ciphertext> dot_products;
    for (int i = 0; i <= rows - kernel_size; ++i) {
        for (int j = 0; j <= cols - kernel_size; ++j) {
            Ciphertext result;
            bool first = true;

            for (int ki = 0; ki < kernel_size; ++ki) {
                for (int kj = 0; kj < kernel_size; ++kj) {
                    int mat_idx = (i + ki) * cols + (j + kj);
                    Ciphertext rotated;
                    evaluator.rotate_vector(encrypted_matrix, mat_idx, gal_keys, rotated);

                    Plaintext kernel_val;
                    encoder.encode(kernel[ki * kernel_size + kj], scale, kernel_val);

                    evaluator.multiply_plain_inplace(rotated, kernel_val);
                    evaluator.rescale_to_next_inplace(rotated);

                    if (first) {
                        result = rotated;
                        first = false;
                    } else {
                        evaluator.add_inplace(result, rotated);
                    }
                }
            }

            dot_products.push_back(result);
        }
    }

    // Step 7: Decrypt and print one result
    Plaintext result_plain;
    vector<double> result_values;
    decryptor.decrypt(dot_products[0], result_plain);
    encoder.decode(result_plain, result_values);

    cout << "First 3x3 Dot Product Result: " << result_values[0] << endl;

    return 0;
}