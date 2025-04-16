// both encrypted, rotate and sum
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

    vector<double> v1 = {1.2, 2.3, 3.1, 4.5};
    vector<double> v2 = {0.9, 1.1, 1.5, 0.8};

    Plaintext pt1, pt2;
    encoder.encode(v1, scale, pt1);
    encoder.encode(v2, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    Ciphertext ct_product;
    evaluator.multiply(ct1, ct2, ct_product);
    evaluator.relinearize_inplace(ct_product, relin_keys);
    evaluator.rescale_to_next_inplace(ct_product);

    for (size_t i = 1; i < v1.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(ct_product, i, gal_keys, rotated);
        evaluator.add_inplace(ct_product, rotated);
    }

    Plaintext result_plain;
    vector<double> result;
    decryptor.decrypt(ct_product, result_plain);
    encoder.decode(result_plain, result);
    cout << "Dot product (v1 • v2): " << result[0] << endl;
    return 0;
}
