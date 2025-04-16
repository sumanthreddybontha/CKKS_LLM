// one encrypted, one plaintext
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
    GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    vector<double> vec_enc = {0.5, 1.0, 1.5, 2.0};
    vector<double> vec_plain = {2.0, 1.5, 1.0, 0.5};

    Plaintext pt_enc, pt_plain;
    encoder.encode(vec_enc, scale, pt_enc);
    encoder.encode(vec_plain, scale, pt_plain);

    Ciphertext ct_enc;
    encryptor.encrypt(pt_enc, ct_enc);

    evaluator.multiply_plain_inplace(ct_enc, pt_plain);
    evaluator.rescale_to_next_inplace(ct_enc);

    for (size_t i = 1; i < vec_enc.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(ct_enc, i, gal_keys, rotated);
        evaluator.add_inplace(ct_enc, rotated);
    }

    Plaintext result_plain;
    vector<double> result;
    decryptor.decrypt(ct_enc, result_plain);
    encoder.decode(result_plain, result);
    cout << "Dot product (enc • plain): " << result[0] << endl;
    return 0;
}
