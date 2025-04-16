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

    vector<double> vec1 = {0.2, 0.3, 0.4, 0.5};
    vector<double> vec2 = {1.0, 0.8, 1.2, 0.9};

    // Split into halves
    vector<double> vec1_l(vec1.begin(), vec1.begin()+2);
    vector<double> vec1_r(vec1.begin()+2, vec1.end());
    vector<double> vec2_l(vec2.begin(), vec2.begin()+2);
    vector<double> vec2_r(vec2.begin()+2, vec2.end());

    Plaintext pt1_l, pt1_r, pt2_l, pt2_r;
    encoder.encode(vec1_l, scale, pt1_l);
    encoder.encode(vec1_r, scale, pt1_r);
    encoder.encode(vec2_l, scale, pt2_l);
    encoder.encode(vec2_r, scale, pt2_r);

    Ciphertext ct1_l, ct1_r, ct2_l, ct2_r;
    encryptor.encrypt(pt1_l, ct1_l);
    encryptor.encrypt(pt1_r, ct1_r);
    encryptor.encrypt(pt2_l, ct2_l);
    encryptor.encrypt(pt2_r, ct2_r);

    Ciphertext prod_l, prod_r;
    evaluator.multiply(ct1_l, ct2_l, prod_l);
    evaluator.relinearize_inplace(prod_l, relin_keys);
    evaluator.rescale_to_next_inplace(prod_l);

    evaluator.multiply(ct1_r, ct2_r, prod_r);
    evaluator.relinearize_inplace(prod_r, relin_keys);
    evaluator.rescale_to_next_inplace(prod_r);

    // Aggregate halves separately
    for (int i = 1; i < 2; i <<= 1) {
        Ciphertext rot_l, rot_r;
        evaluator.rotate_vector(prod_l, i, gal_keys, rot_l);
        evaluator.rotate_vector(prod_r, i, gal_keys, rot_r);
        evaluator.add_inplace(prod_l, rot_l);
        evaluator.add_inplace(prod_r, rot_r);
    }

    evaluator.mod_switch_to_inplace(prod_r, prod_l.parms_id());
    Ciphertext dot;
    evaluator.add(prod_l, prod_r, dot);

    Plaintext result_plain;
    decryptor.decrypt(dot, result_plain);
    vector<double> result;
    encoder.decode(result_plain, result);
    cout << "Chunked dot product result: " << result[0] << endl;

    return 0;
}
