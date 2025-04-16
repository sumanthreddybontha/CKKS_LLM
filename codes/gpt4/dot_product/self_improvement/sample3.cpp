// Version 3
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

vector<double> generate_matrix(int rows, int cols, double value = 1.0) {
    vector<double> mat(rows * cols, value);
    for (int i = 0; i < rows * cols; ++i) mat[i] = (i % 7) + 1;
    return mat;
}

vector<double> extract_patch(const vector<double> &matrix, int row, int col, int stride = 10) {
    vector<double> patch;
    for (int i = 0; i < 3; ++i)
        for (int j = 0; j < 3; ++j)
            patch.push_back(matrix[(row + i) * stride + (col + j)]);
    return patch;
}

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);
    SEALContext context(parms);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    auto matrix = generate_matrix(10, 10);
    vector<double> kernel = {0, 1, 0, 1, -4, 1, 0, 1, 0}; // Laplacian kernel
    Plaintext pt_kernel;
    encoder.encode(kernel, scale, pt_kernel);

    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j) {
            auto patch = extract_patch(matrix, i, j);
            Plaintext pt_patch;
            encoder.encode(patch, scale, pt_patch);
            Ciphertext ct;
            encryptor.encrypt(pt_patch, ct);
            evaluator.multiply_plain_inplace(ct, pt_kernel);
            evaluator.relinearize_inplace(ct, relin_keys);
            evaluator.rescale_to_next_inplace(ct);

            Plaintext result;
            decryptor.decrypt(ct, result);
            vector<double> dec;
            encoder.decode(result, dec);
            double dot_sum = 0;
            for (auto x : dec) dot_sum += x;
            cout << dot_sum << " ";
        }

    cout << endl;
    return 0;
}