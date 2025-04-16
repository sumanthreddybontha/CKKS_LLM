// Chunked Vector Dot Product (2 halves)
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: CKKS encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    SEALContext context(parms);

    // Step 2: Keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    // Step 3: Encryptor, Decryptor, Evaluator, Encoder
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    // Step 4: Vectors split into two parts
    vector<double> vec1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> vec2 = {5.0, 6.0, 7.0, 8.0};

    vector<double> vec1_left(vec1.begin(), vec1.begin() + 2);
    vector<double> vec1_right(vec1.begin() + 2, vec1.end());
    vector<double> vec2_left(vec2.begin(), vec2.begin() + 2);
    vector<double> vec2_right(vec2.begin() + 2, vec2.end());

    // Step 5: Encode and encrypt chunks
    Plaintext pt_v1_l, pt_v1_r, pt_v2_l, pt_v2_r;
    encoder.encode(vec1_left, scale, pt_v1_l);
    encoder.encode(vec1_right, scale, pt_v1_r);
    encoder.encode(vec2_left, scale, pt_v2_l);
    encoder.encode(vec2_right, scale, pt_v2_r);

    Ciphertext ct_v1_l, ct_v1_r, ct_v2_l, ct_v2_r;
    encryptor.encrypt(pt_v1_l, ct_v1_l);
    encryptor.encrypt(pt_v1_r, ct_v1_r);
    encryptor.encrypt(pt_v2_l, ct_v2_l);
    encryptor.encrypt(pt_v2_r, ct_v2_r);

    // Step 6: Multiply corresponding halves
    Ciphertext ct_product_l, ct_product_r;
    evaluator.multiply(ct_v1_l, ct_v2_l, ct_product_l);
    evaluator.relinearize_inplace(ct_product_l, relin_keys);
    evaluator.rescale_to_next_inplace(ct_product_l);

    evaluator.multiply(ct_v1_r, ct_v2_r, ct_product_r);
    evaluator.relinearize_inplace(ct_product_r, relin_keys);
    evaluator.rescale_to_next_inplace(ct_product_r);

    // Step 7: Sum within each half using rotation
    for (int i = 1; i < 2; i <<= 1) {
        Ciphertext rotated_l, rotated_r;
        evaluator.rotate_vector(ct_product_l, i, gal_keys, rotated_l);
        evaluator.add_inplace(ct_product_l, rotated_l);

        evaluator.rotate_vector(ct_product_r, i, gal_keys, rotated_r);
        evaluator.add_inplace(ct_product_r, rotated_r);
    }

    // Step 8: Align levels and sum both halves
    auto target_parms_id = ct_product_l.parms_id();
    evaluator.mod_switch_to_inplace(ct_product_r, target_parms_id);

    Ciphertext final_dot;
    evaluator.add(ct_product_l, ct_product_r, final_dot);

    // Step 9: Decrypt and decode
    Plaintext pt_result;
    decryptor.decrypt(final_dot, pt_result);

    vector<double> result;
    encoder.decode(pt_result, result);
    cout << "Dot product (approximate): " << result[0] << endl;

    return 0;
}
