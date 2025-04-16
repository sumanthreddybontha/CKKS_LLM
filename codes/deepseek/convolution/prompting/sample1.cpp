// Standard scalar addition with helper function
#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

double decrypt_and_decode(Ciphertext &ct, Decryptor &decryptor, CKKSEncoder &encoder, double scale) {
    Plaintext pt;
    decryptor.decrypt(ct, pt);
    vector<double> result;
    encoder.decode(pt, result);
    return result[0];
}

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
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    vector<double> a = {7.5}, b = {2.5};
    Plaintext p1, p2;
    encoder.encode(a, scale, p1);
    encoder.encode(b, scale, p2);

    Ciphertext c1, c2;
    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    evaluator.add_inplace(c1, c2);

    double result = decrypt_and_decode(c1, decryptor, encoder, scale);
    cout << "Decrypted result: " << result << endl;
    return 0;
}
