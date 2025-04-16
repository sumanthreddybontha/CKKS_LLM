// sum using add_many
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

    vector<double> a = {1.0, 2.0, 3.0, 4.0};
    vector<double> b = {0.5, 1.0, 1.5, 2.0};

    Plaintext pa, pb;
    encoder.encode(a, scale, pa);
    encoder.encode(b, scale, pb);

    Ciphertext ca, cb;
    encryptor.encrypt(pa, ca);
    encryptor.encrypt(pb, cb);

    Ciphertext prod;
    evaluator.multiply(ca, cb, prod);
    evaluator.relinearize_inplace(prod, relin_keys);
    evaluator.rescale_to_next_inplace(prod);

    vector<Ciphertext> rotated = {prod};
    for (int i = 1; i < 4; i <<= 1) {
        Ciphertext r;
        evaluator.rotate_vector(prod, i, gal_keys, r);
        rotated.push_back(r);
    }

    Ciphertext dot;
    evaluator.add_many(rotated, dot);

    Plaintext plain_result;
    vector<double> result;
    decryptor.decrypt(dot, plain_result);
    encoder.decode(plain_result, result);
    cout << "Dot product (add_many): " << result[0] << endl;

    return 0;
}
