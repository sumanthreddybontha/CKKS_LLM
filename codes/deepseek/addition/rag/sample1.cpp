#include <iostream>
#include <iomanip>  // Required for setprecision
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main() {
    // Minimal parameters for 128-bit security
    size_t poly_modulus_degree = 8192;
    vector<int> modulus_bits = {60, 40, 40, 60};
    int scale_bits = 40;

    // SEAL setup
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulus_bits));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Crypto components
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Set scale
    double scale = pow(2.0, scale_bits);

    // Values to encrypt
    vector<double> values1 = {3.5};
    vector<double> values2 = {2.25};

    // Encrypt first value
    Plaintext plain1;
    encoder.encode(values1, scale, plain1);
    Ciphertext cipher1;
    encryptor.encrypt(plain1, cipher1);

    // Encrypt second value
    Plaintext plain2;
    encoder.encode(values2, scale, plain2);
    Ciphertext cipher2;
    encryptor.encrypt(plain2, cipher2);

    // Homomorphic addition
    Ciphertext cipher_result;
    evaluator.add(cipher1, cipher2, cipher_result);

    // Decrypt result
    Plaintext plain_result;
    decryptor.decrypt(cipher_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    // Output
    cout << fixed << setprecision(3);
    cout << "Result: " << values1[0] << " + " << values2[0] 
         << " = " << result[0] << endl;
    cout << "Expected: " << values1[0] + values2[0] << endl;

    return 0;
}