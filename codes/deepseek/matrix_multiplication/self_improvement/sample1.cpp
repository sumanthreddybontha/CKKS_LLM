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
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);
    SEALContext context(parms);

    // Step 2: Key generation
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 3: Define input vector [discipline, focus, energy]
    vector<double> attributes = { 7.0, 6.5, 8.2 };
    cout << "Original Attributes: ";
    for (double val : attributes) cout << val << " ";
    cout << endl;

    // Step 4: Encode and Encrypt
    Plaintext plain;
    encoder.encode(attributes, scale, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    // Step 5: Apply f(x) = 1.5x + 0.5

    // Multiply by 1.5
    Plaintext plain_mul;
    encoder.encode(1.5, scale, plain_mul);
    evaluator.multiply_plain_inplace(encrypted, plain_mul);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted);

    // Add 0.5 (adjust scale and level)
    Plaintext plain_add;
    encoder.encode(0.5, encrypted.scale(), plain_add);
    evaluator.mod_switch_to_inplace(plain_add, encrypted.parms_id());
    evaluator.add_plain_inplace(encrypted, plain_add);

    // Step 6: Decrypt and Decode
    Plaintext decrypted;
    decryptor.decrypt(encrypted, decrypted);

    vector<double> result;
    encoder.decode(decrypted, result);

    cout << "Improved Attributes: ";
    for (double val : result) cout << val << " ";
    cout << endl;

    return 0;
}
