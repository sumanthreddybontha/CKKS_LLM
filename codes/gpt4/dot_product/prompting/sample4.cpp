// CKKS Dot Product using Microsoft SEAL (Version 4)
// Unique implementation: includes invariant noise budget tracking during operations
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

    // Step 2: Create SEALContext
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    // Step 3: Key generation
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    auto gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 4: Define vectors
    vector<double> vec1 = {1.5, 2.5, 3.5};
    vector<double> vec2 = {4.5, 3.5, 2.5};

    double scale = pow(2.0, 40);
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    // Step 5: Encrypt vectors
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    cout << "Noise budget after encryption: " << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

    // Step 6: Element-wise multiplication
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);
    cout << "Noise budget after multiplication: " << decryptor.invariant_noise_budget(encrypted_product) << " bits" << endl;

    // Step 7: Sum elements via rotation
    for (size_t i = 1; i < vec1.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_product, i, gal_keys, rotated);
        evaluator.add_inplace(encrypted_product, rotated);
    }
    cout << "Noise budget after summing: " << decryptor.invariant_noise_budget(encrypted_product) << " bits" << endl;

    // Step 8: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Dot product: " << result[0] << endl;

    return 0;
}