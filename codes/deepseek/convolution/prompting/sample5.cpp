// Prints precision difference from expected sum
#include "seal/seal.h"
#include <iostream>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    Plaintext pt1, pt2;
    encoder.encode(6.2, scale, pt1);
    encoder.encode(3.8, scale, pt2);

    Ciphertext c1, c2;
    encryptor.encrypt(pt1, c1);
    encryptor.encrypt(pt2, c2);

    Ciphertext result_ct;
    evaluator.add(c1, c2, result_ct);

    Plaintext result_pt;
    decryptor.decrypt(result_ct, result_pt);
    vector<double> result;
    encoder.decode(result_pt, result);

    double expected = 10.0;
    double error = fabs(result[0] - expected);

    cout << "Decrypted result: " << result[0] << " | Error: " << error << endl;
    return 0;
}
