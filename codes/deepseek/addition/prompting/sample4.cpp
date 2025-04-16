#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    try {
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

        double scale = pow(2.0, 40);
        SEALContext context(parms);

        KeyGenerator keygen(context);
        PublicKey public_key;
        keygen.create_public_key(public_key);
        SecretKey secret_key = keygen.secret_key();

        Encryptor encryptor(context, public_key);
        Decryptor decryptor(context, secret_key);
        CKKSEncoder encoder(context);
        Evaluator evaluator(context);

        vector<double> input1 = {0.0};
        vector<double> input2 = {100.0};

        Plaintext plain1, plain2;
        encoder.encode(input1, scale, plain1);
        encoder.encode(input2, scale, plain2);

        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);

        Ciphertext result;
        evaluator.add(encrypted1, encrypted2, result);

        Plaintext plain_result;
        decryptor.decrypt(result, plain_result);

        vector<double> decoded;
        encoder.decode(plain_result, decoded);

        cout << "Decrypted result: " << decoded[0] << endl;
    } catch (const exception &e) {
        cerr << "Runtime error: " << e.what() << endl;
    }
}
