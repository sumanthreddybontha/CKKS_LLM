// === Variant 4: Multiplication Then Squared ===
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

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    vector<double> input = {1.0, 2.0, 3.0, 4.0};

    Plaintext pt;
    encoder.encode(input, scale, pt);

    Ciphertext ct;
    encryptor.encrypt(pt, ct);

    evaluator.multiply_inplace(ct, ct);
    evaluator.relinearize_inplace(ct, relin_keys);
    evaluator.rescale_to_next_inplace(ct);

    Plaintext result_plain;
    decryptor.decrypt(ct, result_plain);
    vector<double> result;
    encoder.decode(result_plain, result);

    cout << "Input squared (element-wise): ";
    for (double r : result) cout << r << " ";
    cout << endl;
    return 0;
}
