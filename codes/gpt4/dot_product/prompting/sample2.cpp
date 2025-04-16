// One Vector in Plaintext (Faster)

#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    vector<double> vec1 = {1, 2, 3, 4, 5, 6, 7, 8};
    vector<double> vec2 = {8, 7, 6, 5, 4, 3, 2, 1};

    Plaintext pt1, pt2;
    encoder.encode(vec1, scale, pt1);
    encoder.encode(vec2, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    Ciphertext product;
    evaluator.multiply(ct1, ct2, product);
    evaluator.relinearize_inplace(product, relin_keys);
    evaluator.rescale_to_next_inplace(product);

    for (size_t i = 1; i < vec1.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(product, i, gal_keys, rotated);
        evaluator.add_inplace(product, rotated);
    }

    Plaintext plain_result;
    decryptor.decrypt(product, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "Dot product (approximate): " << result[0] << endl;

    return 0;
}
