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
    RelinKeys relin_keys; keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    vector<double> vec1 = {2.0, 1.0, 3.0, 4.0};
    vector<double> vec2 = {0.5, 1.5, 1.0, 2.5};
    vector<double> weights = {1.0, 0.5, 0.8, 1.2};  // simulate embedding weights

    Plaintext pt1, pt2, pt_w;
    encoder.encode(vec1, scale, pt1);
    encoder.encode(vec2, scale, pt2);
    encoder.encode(weights, scale, pt_w);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    // Apply weights to one vector
    evaluator.multiply_plain_inplace(ct1, pt_w);
    evaluator.rescale_to_next_inplace(ct1);

    evaluator.multiply(ct1, ct2, ct1);
    evaluator.relinearize_inplace(ct1, relin_keys);
    evaluator.rescale_to_next_inplace(ct1);

    for (int i = 1; i < 4; i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(ct1, i, gal_keys, rotated);
        evaluator.add_inplace(ct1, rotated);
    }

    Plaintext result_plain;
    decryptor.decrypt(ct1, result_plain);
    vector<double> result;
    encoder.decode(result_plain, result);

    cout << "Weighted dot product (enc): " << result[0] << endl;
    return 0;
}
