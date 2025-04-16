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

    vector<double> vec1 = {0.6, 0.7, 0.8, 0.9};
    vector<double> vec2 = {1.5, 1.0, 1.2, 0.5};

    Plaintext pt1, pt2;
    encoder.encode(vec1, scale, pt1);
    encoder.encode(vec2, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    Ciphertext prod;
    evaluator.multiply(ct1, ct2, prod);
    evaluator.relinearize_inplace(prod, relin_keys);
    evaluator.rescale_to_next_inplace(prod);

    // Rotate and store all versions
    vector<Ciphertext> rotated_terms = {prod};
    for (int i = 1; i < 4; i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(prod, i, gal_keys, rotated);
        rotated_terms.push_back(rotated);
    }

    Ciphertext dot;
    evaluator.add_many(rotated_terms, dot);

    Plaintext result_plain;
    decryptor.decrypt(dot, result_plain);
    vector<double> result;
    encoder.decode(result_plain, result);
    cout << "Dot product (add_many): " << result[0] << endl;

    return 0;
}
