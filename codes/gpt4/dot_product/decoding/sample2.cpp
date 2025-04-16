#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, {60, 40, 40, 60}));

    auto context = SEALContext::Create(parms);
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    auto gal_keys = keygen.galois_keys();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    const size_t rows = 10, cols = 10, kernel_size = 3;
    double scale = pow(2.0, 40);

    // Encode each row individually
    vector<Ciphertext> encrypted_rows(rows);
    for (int i = 0; i < rows; ++i) {
        vector<double> row(cols, 1.0);
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);
        encryptor.encrypt(plain_row, encrypted_rows[i]);
    }

    vector<double> kernel = {
        0.1, 0.2, 0.3,
        0.4, 0.5, 0.6,
        0.7, 0.8, 0.9
    };

    vector<Ciphertext> dot_products;
    for (int i = 0; i <= rows - kernel_size; ++i) {
        for (int j = 0; j <= cols - kernel_size; ++j) {
            Ciphertext result;
            bool first = true;

            for (int ki = 0; ki < kernel_size; ++ki) {
                Ciphertext rotated_row;
                evaluator.rotate_vector(encrypted_rows[i + ki], j, gal_keys, rotated_row);

                for (int kj = 0; kj < kernel_size; ++kj) {
                    Plaintext plain_weight;
                    encoder.encode(kernel[ki * kernel_size + kj], scale, plain_weight);
                    Ciphertext temp = rotated_row;
                    evaluator.multiply_plain_inplace(temp, plain_weight);
                    evaluator.rescale_to_next_inplace(temp);

                    if (first) {
                        result = temp;
                        first = false;
                    } else {
                        evaluator.add_inplace(result, temp);
                    }

                    if (kj < kernel_size - 1)
                        evaluator.rotate_vector_inplace(rotated_row, 1, gal_keys);
                }
            }
            dot_products.push_back(result);
        }
    }

    Plaintext plain_result;
    vector<double> result_values;
    decryptor.decrypt(dot_products[0], plain_result);
    encoder.decode(plain_result, result_values);

    cout << "First Tiled Dot Product Result: " << result_values[0] << endl;

    return 0;
}