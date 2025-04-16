//Basic RAG with inline commentary
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // ✅ CKKS parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(parms);
    double scale = pow(2.0, 40);

    // ✅ Keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    // ✅ Inputs
    vector<double> input1 = {1.5};
    vector<double> input2 = {2.5};

    Plaintext pt1, pt2;
    encoder.encode(input1, scale, pt1);
    encoder.encode(input2, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    // ✅ Addition
    Ciphertext result;
    evaluator.add(ct1, ct2, result);

    // ✅ Decrypt
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> output;
    encoder.decode(plain_result, output);

    cout << "Decrypted result: " << output[0] << endl;
    return 0;
}
