#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    size_t poly_modulus_degree = 16384;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 60}));

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

    double scale = pow(2.0, 40);
    const size_t N = 100;

    vector<double> matrix(N, 2.0);
    vector<double> kernel = {
        0.1, 0.2, 0.3,
        0.4, 0.5, 0.6,
        0.7, 0.8, 0.9
    };

    Plaintext plain_matrix, plain_kernel;
    encoder.encode(matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);

    Ciphertext enc_matrix;
    encryptor.encrypt(plain_matrix, enc_matrix);

    Ciphertext result;
    bool first = true;

    for (int i = 0; i < 9; ++i) {
        Ciphertext rotated;
        evaluator.rotate_vector(enc_matrix, i, gal_keys, rotated);

        Plaintext weight;
        encoder.encode(kernel[i], scale, weight);
        evaluator.multiply_plain_inplace(rotated, weight);
        evaluator.rescale_to_next_inplace(rotated);

        if (first) {
            result = rotated;
            first = false;
        } else {
            evaluator.add_inplace(result, rotated);
        }
    }

    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);

    vector<double> output;
    encoder.decode(plain_result, output);

    cout << "Dot Product Output (first value): " << output[0] << endl;
    return 0;
}