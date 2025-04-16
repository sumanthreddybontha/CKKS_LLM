#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

// Helper: print encryption parameters.
void print_parameters(const SEALContext &context)
{
    auto &parms = context.key_context_data()->parms();
    cout << "Encryption parameters:" << endl;
    cout << "  Scheme: CKKS" << endl;
    cout << "  Poly modulus degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff modulus size: " 
         << context.key_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
}

// Helper function to compute the dot product for a sliding window at position (i,j)
Ciphertext compute_window_dot_product(
    const Ciphertext &encrypted_matrix, 
    int i, int j, 
    int rows, int cols, 
    const vector<double> &kernel, 
    int kernel_size, 
    CKKSEncoder &encoder, 
    Evaluator &evaluator, 
    const GaloisKeys &gal_keys, 
    double scale)
{
    Ciphertext window_result;
    bool first = true;
    for (int ki = 0; ki < kernel_size; ++ki)
    {
        for (int kj = 0; kj < kernel_size; ++kj)
        {
            int shift = (i + ki) * cols + (j + kj);
            Ciphertext rotated;
            evaluator.rotate_vector(encrypted_matrix, shift, gal_keys, rotated);

            Plaintext plain_weight;
            encoder.encode(kernel[ki * kernel_size + kj], scale, plain_weight);

            evaluator.multiply_plain_inplace(rotated, plain_weight);
            evaluator.rescale_to_next_inplace(rotated);

            if (first)
            {
                window_result = rotated;
                first = false;
            }
            else
            {
                evaluator.mod_switch_to_inplace(window_result, rotated.parms_id());
                evaluator.add_inplace(window_result, rotated);
            }
        }
    }
    return window_result;
}

int main() {
    // Set up parameters.
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Key generation with older API calls.
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Prepare rotation keys (all shifts needed for a 10x10 matrix).
    vector<int> steps;
    for (int i = 0; i < 100; ++i)
        steps.push_back(i);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(steps, gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Matrix and kernel definitions.
    const int rows = 10, cols = 10, kernel_size = 3;
    double scale = pow(2.0, 40);
    vector<double> matrix(rows * cols, 1.0);           // 10x10 matrix filled with 1.0
    vector<double> kernel(kernel_size * kernel_size, 0.5); // 3x3 kernel filled with 0.5

    // Encode and encrypt the matrix.
    Plaintext plain_matrix;
    encoder.encode(matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Compute the convolution result for the window at (0,0)
    Ciphertext conv_result = compute_window_dot_product(encrypted_matrix, 0, 0,
                                                        rows, cols, kernel, kernel_size,
                                                        encoder, evaluator, gal_keys, scale);

    // Decrypt and decode the first result.
    Plaintext plain_result;
    vector<double> result_vector;
    decryptor.decrypt(conv_result, plain_result);
    encoder.decode(plain_result, result_vector);
    cout << "Variant 1 - First 3x3 Dot Product Result: " << result_vector[0] << endl;
    return 0;
}