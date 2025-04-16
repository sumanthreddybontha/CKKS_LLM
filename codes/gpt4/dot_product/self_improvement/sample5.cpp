// 1 and 2 to create an optimal version
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: CKKS Parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    double scale = pow(2.0, 40);

    // Step 2: Key Generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 3: Vectors for dot product
    vector<double> vec_encrypted = {1.5, 2.0, 3.5, 4.2};
    vector<double> vec_plain = {0.5, 1.5, 1.0, 0.8};

    // Step 4: Encode
    Plaintext pt_enc, pt_plain;
    encoder.encode(vec_encrypted, scale, pt_enc);
    encoder.encode(vec_plain, scale, pt_plain);

    // Step 5: Encrypt one vector
    Ciphertext ct_enc;
    encryptor.encrypt(pt_enc, ct_enc);

    // Step 6: Multiply (element-wise)
    evaluator.multiply_plain_inplace(ct_enc, pt_plain);
    evaluator.rescale_to_next_inplace(ct_enc);

    // Step 7: Rotate and sum (to simulate inner product)
    for (size_t i = 1; i < vec_encrypted.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(ct_enc, i, gal_keys, rotated);
        evaluator.add_inplace(ct_enc, rotated);
    }

    // Step 8: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(ct_enc, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    // Step 9: Output
    cout << "Approximate dot product result: " << result[0] << endl;

    return 0;
}
