// === Variant 2: One Encrypted Vector and One Plaintext Vector ===
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key; keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    vector<double> encrypted_vec = {1.5, 2.0, 2.5, 3.0};
    vector<double> plain_vec = {2.0, 0.5, 1.0, 1.5};

    Plaintext pt_enc, pt_plain;
    encoder.encode(encrypted_vec, scale, pt_enc);
    encoder.encode(plain_vec, scale, pt_plain);

    Ciphertext ct_enc;
    encryptor.encrypt(pt_enc, ct_enc);

    evaluator.multiply_plain_inplace(ct_enc, pt_plain);
    evaluator.rescale_to_next_inplace(ct_enc);

    Plaintext result_plain;
    decryptor.decrypt(ct_enc, result_plain);

    vector<double> result;
    encoder.decode(result_plain, result);

    cout << "Element-wise multiplication (encrypted • plaintext): ";
    for (double r : result) cout << r << " ";
    cout << endl;
    return 0;
}
