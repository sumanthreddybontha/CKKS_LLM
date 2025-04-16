// Logging at each stage
#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main() {
    cout << "[🔐] Initializing SEAL context..." << endl;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, { 60, 40, 40, 60 }));
    SEALContext context(parms);

    cout << "[🛠️ ] Generating keys..." << endl;
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);
    double scale = pow(2.0, 40);

    cout << "[📦] Encoding and encrypting inputs..." << endl;
    Plaintext p1, p2;
    encoder.encode(20.0, scale, p1);
    encoder.encode(30.0, scale, p2);

    Ciphertext c1, c2;
    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    cout << "[➕] Evaluating addition..." << endl;
    Ciphertext sum;
    evaluator.add(c1, c2, sum);

    Plaintext plain_sum;
    decryptor.decrypt(sum, plain_sum);
    vector<double> result;
    encoder.decode(plain_sum, result);

    cout << "[✅] Final decrypted result: " << result[0] << endl;
    return 0;
}
