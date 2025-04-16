// === Variant 3: Multiplication Followed by Addition with a Constant ===
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

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    vector<double> v1 = {2.0, 4.0, 6.0, 8.0};
    vector<double> v2 = {1.5, 1.5, 1.5, 1.5};

    Plaintext pt1, pt2;
    encoder.encode(v1, scale, pt1);
    encoder.encode(v2, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    evaluator.multiply_inplace(ct1, ct2);
    evaluator.rescale_to_next_inplace(ct1);

    Plaintext constant;
    encoder.encode(3.0, ct1.scale(), constant);
    evaluator.add_plain_inplace(ct1, constant);

    Plaintext result_plain;
    decryptor.decrypt(ct1, result_plain);

    vector<double> result;
    encoder.decode(result_plain, result);

    cout << "(v1 * v2) + 3.0: ";
    for (double r : result) cout << r << " ";
    cout << endl;
    return 0;
}