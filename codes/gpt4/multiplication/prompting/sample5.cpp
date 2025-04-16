#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

int main() {
    // Step 1: Set up encryption parameters
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(
        poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Create SEALContext
    seal::SEALContext context(parms);

    // Step 3: Generate keys
    seal::KeyGenerator keygen(context);

    seal::PublicKey public_key;
    keygen.create_public_key(public_key);

    seal::SecretKey secret_key = keygen.secret_key();

    seal::RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Step 4: Create Encryptor, Decryptor, Evaluator
    seal::Encryptor encryptor(context, public_key);
    seal::Decryptor decryptor(context, secret_key);
    seal::Evaluator evaluator(context);
    seal::CKKSEncoder encoder(context);

    // Step 5: Set scale
    double scale = pow(2.0, 40);

    // Step 6: Encode and encrypt input values
    std::vector<double> input1 = {2.0};
    std::vector<double> input2 = {3.0};

    seal::Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);

    seal::Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 7: Multiply encrypted values
    seal::Ciphertext encrypted_result;
    evaluator.multiply(encrypted1, encrypted2, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 8: Decrypt and decode
    seal::Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    std::vector<double> result;
    encoder.decode(plain_result, result);

    std::cout << "Result: " << result[0] << std::endl;

    return 0;
}