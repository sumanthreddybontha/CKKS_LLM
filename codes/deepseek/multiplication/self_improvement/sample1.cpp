#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main() {
    // Set up parameters
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 40, 40, 40, 40}));
    
    double scale = pow(2.0, 20);

    // Create context with error checking
    SEALContext context(params);
    if (!context.parameters_set()) {
        cerr << "Error: Invalid encryption parameters" << endl;
        return -1;
    }

    // Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Prepare values
    vector<double> input1{3.1415}, input2{2.7182};
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);

    // Encryption
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Multiplication
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Decryption
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);

    // Decode and compute relative error
    vector<double> result;
    encoder.decode(plain_result, result);
    
    double expected = input1[0] * input2[0];
    double actual = result[0];
    double rel_error = abs(expected - actual) / expected;

    // Output only the final result and relative error
    cout << "Result: " << actual << endl;
    cout << "Relative Error: " << rel_error << endl;

    return 0;
}