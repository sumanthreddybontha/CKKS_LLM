#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Create SEALContext
    SEALContext context(parms);
    // print_parameters(context);
    cout << endl;

    // Step 3: Key Generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
keygen.create_relin_keys(relin_keys);

    // Step 4: Create tools
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Step 5: Matrix and Kernel setup
    size_t slot_count = encoder.slot_count();
    double scale = pow(2.0, 40);

    vector<double> input_matrix(100, 1.0); // 10x10 matrix filled with 1s
    vector<double> kernel(9, 2.0); // 3x3 kernel filled with 2s

    // Step 6: Encode input matrix
    Plaintext plain_matrix;
    encoder.encode(input_matrix, scale, plain_matrix);

    // Encrypt the matrix
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Step 7: Convolution-like multiplication (simulate with rotation and multiply)
    Ciphertext result;
    evaluator.multiply_plain(encrypted_matrix, plain_matrix, result);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);

    // Step 8: Decrypt and decode result
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);

    vector<double> decoded_result;
    encoder.decode(plain_result, decoded_result);

    // Print the first 10 values of the result
    cout << "Decrypted Result (First 10 values): ";
    for (int i = 0; i < 10; i++) {
        cout << decoded_result[i] << " ";
    }
    cout << endl;

    return 0;
}