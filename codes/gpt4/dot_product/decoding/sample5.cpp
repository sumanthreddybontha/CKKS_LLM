#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
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
    vector<double> matrix(100, 2.0);
    vector<double> kernel = {1, 0, -1, 2, 0, -2, 1, 0, -1};  // Example kernel

    Plaintext plain_matrix, plain_kernel;
    encoder.encode(matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);

    Ciphertext enc_matrix, enc_kernel;
    encryptor.encrypt(plain_matrix, enc_matrix);
    encryptor.encrypt(plain_kernel, enc_kernel);

    Ciphertext result;
    bool first = true;

    for (int i = 0; i < 9; ++i) {
        Ciphertext rotated;
        evaluator.rotate_vector(enc_matrix, i, gal_keys, rotated);

        Ciphertext temp;
        evaluator.multiply(rotated, enc_kernel, temp);
        evaluator.relinearize_inplace(temp, relin_keys);
        evaluator.rescale_to_next_inplace(temp);

        if (first) {
            result = temp;
            first = false;
        } else {
            evaluator.add_inplace(result, temp);
        }
    }

    Plaintext result_plain;
    decryptor.decrypt(result, result_plain);
    vector<double> values;
    encoder.decode(result_plain, values);

    cout << "Encrypted Kernel Result (first): " << values[0] << endl;
    return 0;
}