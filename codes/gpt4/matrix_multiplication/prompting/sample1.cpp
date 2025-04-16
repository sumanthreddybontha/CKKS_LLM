// Code 1: Basic CKKS Matrix Multiplication (2x2)
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);

    // Step 2: Key generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    GaloisKeys gal_keys;

    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(gal_keys);

    // Step 3: Create tools
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    // Step 4: Define 2x2 matrices A and B
    vector<double> A = {1.0, 2.0, 3.0, 4.0}; // Row-major
    vector<double> B = {5.0, 6.0, 7.0, 8.0}; // Row-major

    Plaintext plain_A, plain_B;
    encoder.encode(A, scale, plain_A);
    encoder.encode(B, scale, plain_B);

    Ciphertext enc_A, enc_B;
    encryptor.encrypt(plain_A, enc_A);
    encryptor.encrypt(plain_B, enc_B);

    // Step 5: Homomorphic matrix multiplication (A × B)
    Ciphertext temp1;
    evaluator.multiply_plain(enc_A, plain_B, temp1);
    evaluator.rescale_to_next_inplace(temp1);

    // Decrypt to check result
    Plaintext result_plain;
    vector<double> result_vec;

    decryptor.decrypt(temp1, result_plain);
    encoder.decode(result_plain, result_vec);

    cout << "Partial Homomorphic Matrix Multiplication Result (element-wise):" << endl;
    for (auto &val : result_vec) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}