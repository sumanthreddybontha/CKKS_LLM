// Uses consistent CKKS parameter settings, properly generates keys (including public, secret, relinearization, 
// and Galois keys), and performs a straightforward sequence of steps: encoding plaintexts, encrypting them, multiplying the ciphertexts
// Using Responses 1 and 3
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

    // Step 2: Generate keys
    KeyGenerator keygen(context);
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;
    std::stringstream stream;
    public_key_serial.save(stream);
    public_key.load(context, stream);
    SecretKey secret_key = keygen.secret_key();

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Step 3: Create encryptor, evaluator, decryptor, and encoder
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 4: Define and encode two input vectors
    vector<double> vector_a = {1.1, 2.2, 3.3, 4.4};
    vector<double> vector_b = {5.5, 6.6, 7.7, 8.8};
    Plaintext plain_a, plain_b;
    encoder.encode(vector_a, scale, plain_a);
    encoder.encode(vector_b, scale, plain_b);

    // Step 5: Encrypt the plaintext vectors
    Ciphertext encrypted_a, encrypted_b;
    encryptor.encrypt(plain_a, encrypted_a);
    encryptor.encrypt(plain_b, encrypted_b);

    // Step 6: Perform element-wise multiplication
    Ciphertext result = encrypted_a;
    evaluator.multiply_inplace(result, encrypted_b);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);

    // Step 7: Decrypt and decode the result
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