#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <memory>

using namespace std;
using namespace seal;

int main() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));

    auto context = make_shared<SEALContext>(parms);
    double scale = pow(2.0, 40);

    // Generate keys
    KeyGenerator keygen(*context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Create encryptor, evaluator, decryptor, encoder
    Encryptor* encryptor = new Encryptor(*context, public_key);
    Evaluator* evaluator = new Evaluator(*context);
    Decryptor* decryptor = new Decryptor(*context, secret_key);
    CKKSEncoder* encoder = new CKKSEncoder(*context);

    size_t slot_count = encoder->slot_count();
    cout << "CKKS slot count: " << slot_count << endl;

    // Example matrices A and B (2x2)
    vector<vector<double>> A = {
        {1.0, 2.0},
        {3.0, 4.0}
    };

    vector<vector<double>> B = {
        {5.0, 6.0},
        {7.0, 8.0}
    };

    // Flatten rows and columns
    vector<double> a_row0 = A[0];
    vector<double> a_row1 = A[1];

    vector<double> b_col0 = {B[0][0], B[1][0]};
    vector<double> b_col1 = {B[0][1], B[1][1]};

    // Encode and encrypt
    Plaintext a0_plain, a1_plain, b0_plain, b1_plain;
    encoder->encode(a_row0, scale, a0_plain);
    encoder->encode(a_row1, scale, a1_plain);
    encoder->encode(b_col0, scale, b0_plain);
    encoder->encode(b_col1, scale, b1_plain);

    Ciphertext a0_encrypted, a1_encrypted, b0_encrypted, b1_encrypted;
    encryptor->encrypt(a0_plain, a0_encrypted);
    encryptor->encrypt(a1_plain, a1_encrypted);
    encryptor->encrypt(b0_plain, b0_encrypted);
    encryptor->encrypt(b1_plain, b1_encrypted);

    // Multiply and relinearize
    Ciphertext c00, c01, c10, c11;

    evaluator->multiply(a0_encrypted, b0_encrypted, c00);
    evaluator->relinearize_inplace(c00, relin_keys);
    evaluator->rescale_to_next_inplace(c00);

    evaluator->multiply(a0_encrypted, b1_encrypted, c01);
    evaluator->relinearize_inplace(c01, relin_keys);
    evaluator->rescale_to_next_inplace(c01);

    evaluator->multiply(a1_encrypted, b0_encrypted, c10);
    evaluator->relinearize_inplace(c10, relin_keys);
    evaluator->rescale_to_next_inplace(c10);

    evaluator->multiply(a1_encrypted, b1_encrypted, c11);
    evaluator->relinearize_inplace(c11, relin_keys);
    evaluator->rescale_to_next_inplace(c11);

    // Decrypt and decode
    Plaintext c00_plain, c01_plain, c10_plain, c11_plain;
    vector<double> r00, r01, r10, r11;

    decryptor->decrypt(c00, c00_plain);
    encoder->decode(c00_plain, r00);

    decryptor->decrypt(c01, c01_plain);
    encoder->decode(c01_plain, r01);

    decryptor->decrypt(c10, c10_plain);
    encoder->decode(c10_plain, r10);

    decryptor->decrypt(c11, c11_plain);
    encoder->decode(c11_plain, r11);

    // Output result
    cout << "\nResult matrix (approximate):\n";
    cout << "[ " << r00[0] << ", " << r01[0] << " ]" << endl;
    cout << "[ " << r10[0] << ", " << r11[0] << " ]" << endl;

    // Clean up heap allocations
    delete encryptor;
    delete evaluator;
    delete decryptor;
    delete encoder;

    return 0;
}
