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

    // Simulated: user query is private → encrypted; doc vector is public → plaintext
    vector<double> query_vec = {0.9, 1.1, -0.5, 0.3};
    vector<double> doc_vec   = {1.0, 0.8, -1.2, 0.7};

    Plaintext pt_query, pt_doc;
    encoder.encode(query_vec, scale, pt_query);
    encoder.encode(doc_vec, scale, pt_doc);

    Ciphertext ct_query;
    encryptor.encrypt(pt_query, ct_query);

    // Multiply only once with plain document vector
    Ciphertext prod;
    evaluator.multiply_plain(ct_query, pt_doc, prod);
    evaluator.rescale_to_next_inplace(prod);

    for (int i = 1; i < 4; i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(prod, i, gal_keys, rotated);
        evaluator.add_inplace(prod, rotated);
    }

    Plaintext pt_result;
    decryptor.decrypt(prod, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);

    cout << "Dot product (enc query × plain doc): " << result[0] << endl;
    return 0;
}
