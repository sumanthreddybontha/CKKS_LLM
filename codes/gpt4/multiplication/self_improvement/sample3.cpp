// Scaling in Multiple Stages
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
    double scale1 = pow(2.0, 50);
    double scale2 = pow(2.0, 40);

    SEALContext context(parms);
    KeyGenerator keygen(context);

    // Correctly handle the public key
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;
    std::stringstream stream;
    public_key_serial.save(stream);
    public_key.load(context, stream);

    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    vector<double> vector_a = {1.1, 2.2, 3.3, 4.4};
    vector<double> vector_b = {5.5, 6.6, 7.7, 8.8};
    Plaintext plain_a, plain_b;
    encoder.encode(vector_a, scale1, plain_a);
    encoder.encode(vector_b, scale2, plain_b);

    Ciphertext encrypted_a, encrypted_b;
    encryptor.encrypt(plain_a, encrypted_a);
    encryptor.encrypt(plain_b, encrypted_b);

    // Perform multiplication and adjust scale
    evaluator.multiply_inplace(encrypted_a, encrypted_b);
    evaluator.rescale_to_next_inplace(encrypted_a);

    // Decrypt and decode the result
    Plaintext decrypted_result;
    decryptor.decrypt(encrypted_a, decrypted_result);
    vector<double> result;
    encoder.decode(decrypted_result, result);

    cout << "Decrypted result (approx): ";
    for (const auto &val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
