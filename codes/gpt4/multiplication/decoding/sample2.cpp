#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set CKKS encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    double scale = pow(2.0, 40);
    SEALContext context(parms);

    // Step 2: Generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 3: Create input vector to encode and encrypt
    vector<double> input = {3.1415, 2.7182, -1.4142, 0.5772};

    cout << "\nOriginal Input:\n";
    for (double val : input) {
        cout << val << " ";
    }
    cout << endl;

    // Step 4: Encode input
    Plaintext plain;
    encoder.encode(input, scale, plain);

    // Step 5: Encrypt
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    // Step 6: Decrypt
    Plaintext decrypted_plain;
    decryptor.decrypt(encrypted, decrypted_plain);

    // Step 7: Decode
    vector<double> decoded;
    encoder.decode(decrypted_plain, decoded);

    // Step 8: Print decoded result
    cout << "\nDecoded Result:\n";
    for (double val : decoded) {
        cout << fixed << setprecision(5) << val << " ";
    }
    cout << endl;

    return 0;
}