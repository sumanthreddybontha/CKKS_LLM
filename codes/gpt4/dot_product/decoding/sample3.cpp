#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context)
{
    auto &parms = context.key_context_data()->parms();
    cout << "Encryption parameters:" << endl;
    cout << "  Scheme: CKKS" << endl;
    cout << "  Poly modulus degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff modulus size: " 
         << context.key_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
}

int main() {
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    vector<int> steps;
    for (int i = 0; i < 100; i++) 
        steps.push_back(i);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(steps, gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    
    const int rows = 10, cols = 10, kernel_size = 3;
    double scale = pow(2.0, 40);
    vector<double> matrix(rows * cols, 1.0);
    vector<double> kernel(kernel_size * kernel_size, 0.5);

    Plaintext plain_matrix;
    encoder.encode(matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Lambda function to compute the convolution dot product at (i,j)
    auto compute_window = [&](int i, int j) -> Ciphertext {
        Ciphertext result;
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
                    result = rotated;
                    first = false;
                }
                else
                {
                    evaluator.mod_switch_to_inplace(result, rotated.parms_id());
                    evaluator.add_inplace(result, rotated);
                }
            }
        }
        return result;
    };

    // Compute the result for the window at (0,0)
    Ciphertext conv_result = compute_window(0, 0);

    Plaintext plain_result;
    vector<double> result_vector;
    decryptor.decrypt(conv_result, plain_result);
    encoder.decode(plain_result, result_vector);
    cout << "Variant 2 - First 3x3 Dot Product Result: " << result_vector[0] << endl;

    return 0;
}