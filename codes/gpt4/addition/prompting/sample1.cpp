#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    try {
        // Setup encryption parameters for CKKS scheme
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

        double scale = pow(2.0, 40);
        SEALContext context(parms);

        cout << "✅ SEAL context created." << endl;

        // Key generation
        KeyGenerator keygen(context);
        PublicKey public_key;
        keygen.create_public_key(public_key);
        SecretKey secret_key = keygen.secret_key();

        Encryptor encryptor(context, public_key);
        Decryptor decryptor(context, secret_key);
        Evaluator evaluator(context);
        CKKSEncoder encoder(context);

        // Prepare input
        vector<double> input1 = {3.5};
        vector<double> input2 = {2.5};

        Plaintext plain1, plain2;
        encoder.encode(input1, scale, plain1);
        encoder.encode(input2, scale, plain2);

        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);

        cout << "✅ Encryption complete." << endl;

        // Homomorphic addition
        Ciphertext encrypted_result;
        evaluator.add(encrypted1, encrypted2, encrypted_result);

        cout << "✅ Homomorphic addition done." << endl;

        // Decrypt and decode
        Plaintext plain_result;
        decryptor.decrypt(encrypted_result, plain_result);

        vector<double> result;
        encoder.decode(plain_result, result);

        cout << "✅ Decrypted result: " << result[0] << endl;

    } catch (const exception &e) {
        cerr << "❌ Runtime error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
