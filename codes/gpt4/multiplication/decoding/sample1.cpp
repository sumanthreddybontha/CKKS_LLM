#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

void print_matrix(const vector<double>& mat, size_t rows, size_t cols) {
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            cout << mat[i * cols + j] << "\t";
        }
        cout << endl;
    }
}

int main() {
    // Step 1: Encryption Parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    cout << "CKKS context created.\n";

    // Step 2: Keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Slots available: " << slot_count << endl;

    // Step 3: Create input matrix
    size_t rows = 10, cols = 10;
    vector<double> matrix(rows * cols);
    for (size_t i = 0; i < matrix.size(); ++i) {
        matrix[i] = static_cast<double>(i + 1); // 1 to 100
    }

    cout << "\nOriginal matrix:\n";
    print_matrix(matrix, rows, cols);

    // Step 4: Encode and encrypt matrix
    Plaintext plain_matrix;
    encoder.encode(matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Step 5: Encode a kernel value (e.g., center weight -4.0)
    vector<double> kernel_weight(slot_count, -4.0);
    Plaintext plain_weight;
    encoder.encode(kernel_weight, scale, plain_weight);

    // Step 6: Multiply and rescale
    Ciphertext result;
    evaluator.multiply_plain(encrypted_matrix, plain_weight, result);
    evaluator.rescale_to_next_inplace(result);

    // Step 7: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> decoded_result;
    encoder.decode(plain_result, decoded_result);

    cout << "\nResult of homomorphic multiplication with kernel weight (-4.0):\n";
    print_matrix(decoded_result, rows, cols);

    return 0;
}