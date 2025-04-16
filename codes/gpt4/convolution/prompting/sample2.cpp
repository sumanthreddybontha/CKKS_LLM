// Adds a scalar to an encrypted number
#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    Plaintext plain_scalar;
    encoder.encode(1.0, scale, plain_scalar); // scalar

    Plaintext pt;
    encoder.encode(vector<double>{9.0}, scale, pt);
    Ciphertext ct;
    encryptor.encrypt(pt, ct);

    evaluator.add_plain_inplace(ct, plain_scalar); // ct + 1.0

    Plaintext result_pt;
    decryptor.decrypt(ct, result_pt);
    vector<double> result;
    encoder.decode(result_pt, result);

    cout << "Decrypted result: " << result[0] << endl;
    return 0;
}
