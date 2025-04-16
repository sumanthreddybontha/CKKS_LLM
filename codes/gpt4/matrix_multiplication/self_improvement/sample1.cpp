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

    // Step 2: Generate keys and serialize/deserialize them properly
    KeyGenerator keygen(context);

    // Handle public key
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;
    std::stringstream public_key_stream;
    public_key_serial.save(public_key_stream);
    public_key.load(context, public_key_stream);

    SecretKey secret_key = keygen.secret_key();

    // Handle relinearization keys
    Serializable<RelinKeys> relin_keys_serial = keygen.create_relin_keys();
    RelinKeys relin_keys;
    std::stringstream relin_key_stream;
    relin_keys_serial.save(relin_key_stream);
    relin_keys.load(context, relin_key_stream);

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

    Ciphertext encrypted_a, encrypted_b;
    encryptor.encrypt(plain_a, encrypted_a);
    encryptor.encrypt(plain_b, encrypted_b);

    // Perform element-wise multiplication
    Ciphertext result = encrypted_a;
    evaluator.multiply_inplace(result, encrypted_b);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);

    // Decrypt and decode the result
    Plaintext decrypted_result;
    decryptor.decrypt(result, decrypted_result);
    vector<double> decoded_result;
    encoder.decode(decrypted_result, decoded_result);

    // Output the approximated result
    cout << "Decrypted result (approx): ";
    for (const auto &val : decoded_result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
