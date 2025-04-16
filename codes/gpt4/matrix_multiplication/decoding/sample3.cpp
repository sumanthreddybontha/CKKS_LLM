#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters params;
    shared_ptr<SEALContext> context;
    size_t slot_count;

    setup_ckks_context(context, params, slot_count);

    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    CKKSEncoder encoder(context);
    Encryptor encryptor(context);
    Evaluator evaluator(context);
    Decryptor decryptor(context);

    generate_keys(context, public_key, secret_key, relin_keys, galois_keys,
                  encoder, encryptor, evaluator, decryptor);

    double scale = pow(2.0, 40);

    // Matrix 2x2
    vector<vector<double>> matrix = {
        {2.0, 3.0},
        {4.0, 1.0}
    };

    // Vector 2x1
    vector<double> vec = {1.0, 2.0};

    // Pad to slot count
    vec.resize(slot_count, 0.0);
    for (auto &row : matrix) row.resize(slot_count, 0.0);

    Ciphertext encrypted_vec;
    encode_encrypt_vector(vec, scale, encoder, encryptor, encrypted_vec);

    Ciphertext encrypted_result = matrix_vector_multiply(matrix, encrypted_vec, encoder, evaluator, galois_keys, relin_keys, scale);

    vector<double> result;
    decrypt_and_decode(encrypted_result, decryptor, encoder, result);

    cout << "Decrypted result (first few values): ";
    for (size_t i = 0; i < 4; ++i)
        cout << result[i] << " ";
    cout << endl;

    return 0;
}
