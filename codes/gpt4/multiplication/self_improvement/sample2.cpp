// Alternating Encryption and Multiplication

#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <sstream>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up encryption parameters for CKKS
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(parms);

    // Step 2: Generate keys and serialize public key
    KeyGenerator keygen(context);
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;

    // Serialize and load the public key
    std::stringstream stream;
    public_key_serial.save(stream);
    public_key.load(context, stream);

    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 3: Define and encode two input vectors
    vector<double> vector_a = {1.1, 2.2, 3.3, 4.4};
    vector<double> vector_b = {5.5, 6.6, 7.7, 8.8};
    Plaintext plain_a, plain_b;
    encoder.encode(vector_a, scale, plain_a);
    encoder.encode(vector_b, scale, plain_b);

    // Encrypt vector_a only
    Ciphertext encrypted_a;
    encryptor.encrypt(plain_a, encrypted_a);

    // Perform multiplication with plain_b
    evaluator.multiply_plain_inplace(encrypted_a, plain_b);

    // Encrypt the intermediate result
    Plaintext intermediate_result;
    decryptor.decrypt(encrypted_a, intermediate_result);
    Ciphertext encrypted_result;
    encryptor.encrypt(intermediate_result, encrypted_result);

    // Decrypt and decode the final result
    Plaintext decrypted_result;
    decryptor.decrypt(encrypted_result, decrypted_result);
    vector<double> result;
    encoder.decode(decrypted_result, result);

    cout << "Decrypted result (approx): ";
    for (const auto &val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
