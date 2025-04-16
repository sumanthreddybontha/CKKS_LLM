#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

// Matrix multiplication helper (not encrypted)
vector<vector<double>> matmul(const vector<vector<double>> &A, const vector<vector<double>> &B) {
    size_t n = A.size(), m = B[0].size(), p = B.size();
    vector<vector<double>> result(n, vector<double>(m, 0.0));
    for (size_t i = 0; i < n; ++i)
        for (size_t j = 0; j < m; ++j)
            for (size_t k = 0; k < p; ++k)
                result[i][j] += A[i][k] * B[k][j];
    return result;
}

int main() {
    // Set encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 60 }));

    SEALContext context(parms);
    auto &context_data = *context.key_context_data();

    // Key generation
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);


    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Define input vectors for multiplication (flattened matrices)
    vector<double> vec1 = { 1.0, 2.0, 3.0, 4.0 }; // 2x2 matrix A
    vector<double> vec2 = { 5.0, 6.0, 7.0, 8.0 }; // 2x2 matrix B (column-major format for rotation-based dot)

    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Element-wise multiplication
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Decrypt and decode result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Decrypted result (element-wise product): ";
    for (double val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
