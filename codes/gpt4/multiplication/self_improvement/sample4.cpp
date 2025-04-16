// Applying Multiple Rounds of Rotation
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <sstream>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    KeyGenerator keygen(context);

    // Correctly handle the public key
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;
    std::stringstream pubkey_stream;
    public_key_serial.save(pubkey_stream);
    public_key.load(context, pubkey_stream);

    SecretKey secret_key = keygen.secret_key();

    // Correctly handle the Galois keys
    Serializable<GaloisKeys> galois_keys_serial = keygen.create_galois_keys();
    GaloisKeys galois_keys;
    std::stringstream galois_stream;
    galois_keys_serial.save(galois_stream);
    galois_keys.load(context, galois_stream);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    vector<double> vector_a = {1.1, 2.2, 3.3, 4.4};
    vector<double> vector_b = {5.5, 6.6, 7.7, 8.8};
    Plaintext plain_a, plain_b;
    encoder.encode(vector_a, scale, plain_a);
    encoder.encode(vector_b, scale, plain_b);

    Ciphertext encrypted_a, encrypted_b;
    encryptor.encrypt(plain_a, encrypted_a);
    encryptor.encrypt(plain_b, encrypted_b);

    // Perform multiple rounds of rotation and accumulation
    Ciphertext result = encrypted_a;
    for (size_t i = 0; i < vector_a.size(); i++) {
        Ciphertext rotated_a;
        evaluator.rotate_vector(encrypted_a, i, galois_keys, rotated_a);
        evaluator.multiply_inplace(rotated_a, encrypted_b);
        evaluator.add_inplace(result, rotated_a);
    }

    // Decrypt and decode the result
    Plaintext decrypted_result;
    decryptor.decrypt(result, decrypted_result);
    vector<double> result_vector;
    encoder.decode(decrypted_result, result_vector);

    cout << "Decrypted result (approx): ";
    for (const auto &val : result_vector) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}

