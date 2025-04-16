// Version 1
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // 1. CKKS Parameters
    size_t poly_modulus_degree = 8192;
    double scale = pow(2.0, 40);
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    // 2. Keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // 3. Matrix and Kernel Initialization
    vector<double> matrix(100);
    vector<double> kernel = {
        1.0, 0.0, -1.0,
        2.0, 0.0, -2.0,
        1.0, 0.0, -1.0
    };

    for (int i = 0; i < 100; ++i)
        matrix[i] = i % 10; // Fill 10x10 matrix row-major

    // 4. Encode kernel
    Plaintext plain_kernel;
    encoder.encode(kernel, scale, plain_kernel);

    // 5. Encrypt matrix patches and compute dot product
    vector<double> result;
    for (int i = 0; i <= 7; ++i) {
        for (int j = 0; j <= 7; ++j) {
            vector<double> patch;
            for (int ki = 0; ki < 3; ++ki)
                for (int kj = 0; kj < 3; ++kj)
                    patch.push_back(matrix[(i + ki) * 10 + (j + kj)]);

            Plaintext plain_patch;
            encoder.encode(patch, scale, plain_patch);
            Ciphertext encrypted_patch;
            encryptor.encrypt(plain_patch, encrypted_patch);

            Ciphertext dot_result;
            evaluator.multiply_plain(encrypted_patch, plain_kernel, dot_result);
            evaluator.relinearize_inplace(dot_result, relin_keys);
            evaluator.rescale_to_next_inplace(dot_result);

            // Sum all elements (slot sum)
            Plaintext plain_mask;
            encoder.encode(vector<double>(9, 1.0), scale, plain_mask);
            evaluator.multiply_plain_inplace(dot_result, plain_mask);

            Plaintext plain_result;
            decryptor.decrypt(dot_result, plain_result);
            vector<double> decoded;
            encoder.decode(plain_result, decoded);
            result.push_back(decoded[0]);
        }
    }

    cout << "Encrypted Dot Products (First 5): ";
    for (int i = 0; i < 5; ++i)
        cout << result[i] << " ";
    cout << endl;

    return 0;
}