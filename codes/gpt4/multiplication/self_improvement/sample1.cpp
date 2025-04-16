#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
#include <sstream> // For stream handling

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up encryption parameters for CKKS
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(params);

    // Step 2: Generate keys and create encryptor, evaluator, and decryptor
    KeyGenerator keygen(context);
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;

    // Serialize and load the public key using a stream
    std::stringstream stream;
    public_key_serial.save(stream); // Save into a stream
    public_key.load(context, stream); // Load from the stream

    SecretKey secret_key = keygen.secret_key();

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 3: Define and encode two input vectors
    vector<double> vector_a = {1.1, 2.2, 3.3, 4.4};
    vector<double> vector_b = {5.5, 6.6, 7.7, 8.8};
    Plaintext plaintext_a, plaintext_b;
    encoder.encode(vector_a, scale, plaintext_a);
    encoder.encode(vector_b, scale, plaintext_b);

    // Step 4: Encrypt the plaintext vectors
    Ciphertext encrypted_a, encrypted_b;
    encryptor.encrypt(plaintext_a, encrypted_a);
    encryptor.encrypt(plaintext_b, encrypted_b);

    // Step 5: Perform element-wise multiplication using a variation (e.g., rotate-and-sum)
    Ciphertext partial_result = encrypted_a; // Start with first element multiplication
    evaluator.multiply_inplace(partial_result, encrypted_b);
    evaluator.relinearize_inplace(partial_result, relin_keys);

    for (size_t i = 1; i < vector_a.size(); i++) {
        Ciphertext rotated_b;
        evaluator.rotate_vector(encrypted_b, i, galois_keys, rotated_b);
        Ciphertext partial_sum = encrypted_a;
        evaluator.multiply_inplace(partial_sum, rotated_b);
        evaluator.relinearize_inplace(partial_sum, relin_keys);
        evaluator.add_inplace(partial_result, partial_sum);
    }

    // Step 6: Decrypt and decode the result
    Plaintext decrypted_result;
    decryptor.decrypt(partial_result, decrypted_result);
    vector<double> result;
    encoder.decode(decrypted_result, result);

    // Output the approximated result
    cout << "Decrypted result (approx): ";
    for (const auto &val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
