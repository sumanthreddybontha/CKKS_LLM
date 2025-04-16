// Apply Weights Before Dot Product
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

    vector<double> vec1 = {2.0, 4.0, 6.0, 8.0};
    vector<double> vec2 = {1.0, 2.0, 3.0, 4.0};
    vector<double> weights = {0.5, 1.5, 1.0, 2.0};

    Plaintext pt1, pt2, pt_weights;
    encoder.encode(vec1, scale, pt1);
    encoder.encode(vec2, scale, pt2);
    encoder.encode(weights, scale, pt_weights);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    // Apply weights to ct1
    evaluator.multiply_plain_inplace(ct1, pt_weights);
    evaluator.rescale_to_next_inplace(ct1);

    Ciphertext product;
    evaluator.multiply(ct1, ct2, product);
    evaluator.relinearize_inplace(product, relin_keys);
    evaluator.rescale_to_next_inplace(product);

    for (int i = 1; i < vec1.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(product, i, gal_keys, rotated);
        evaluator.add_inplace(product, rotated);
    }

    Plaintext result_pt;
    decryptor.decrypt(product, result_pt);

    vector<double> result;
    encoder.decode(result_pt, result);
    cout << "Weighted dot product (approximate): " << result[0] << endl;

    return 0;
}
