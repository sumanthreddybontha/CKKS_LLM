// Version 2
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <random>

using namespace std;
using namespace seal;

int main() {
    size_t poly_modulus_degree = 8192;
    double scale = pow(2.0, 30);
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 30, 30, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Random Matrix and Kernel
    default_random_engine gen;
    uniform_real_distribution<double> dist(0.0, 5.0);
    vector<double> matrix(100), kernel(9);
    for (auto &x : matrix) x = dist(gen);
    for (auto &k : kernel) k = dist(gen);

    Plaintext plain_kernel;
    encoder.encode(kernel, scale, plain_kernel);

    vector<double> output;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            vector<double> patch;
            for (int ki = 0; ki < 3; ++ki)
                for (int kj = 0; kj < 3; ++kj)
                    patch.push_back(matrix[(i + ki) * 10 + (j + kj)]);

            Plaintext pt;
            encoder.encode(patch, scale, pt);
            Ciphertext ct;
            encryptor.encrypt(pt, ct);
            evaluator.multiply_plain_inplace(ct, plain_kernel);
            evaluator.relinearize_inplace(ct, relin_keys);
            evaluator.rescale_to_next_inplace(ct);

            Plaintext sum_result;
            decryptor.decrypt(ct, sum_result);
            vector<double> decoded;
            encoder.decode(sum_result, decoded);
            double sum = 0;
            for (double d : decoded) sum += d;
            output.push_back(sum);
        }
    }

    cout << "Output[0]: " << output[0] << endl;
    return 0;
}