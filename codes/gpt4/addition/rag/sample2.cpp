'''Using context parameters from documentation'''
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 60}));

    SEALContext context(parms);
    double scale = pow(2.0, 40);

    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor enc(context, pk);
    Decryptor dec(context, sk);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    vector<double> a = {12.0}, b = {8.0};
    Plaintext pa, pb;
    encoder.encode(a, scale, pa);
    encoder.encode(b, scale, pb);

    Ciphertext ea, eb;
    enc.encrypt(pa, ea);
    enc.encrypt(pb, eb);

    Ciphertext result;
    evaluator.add(ea, eb, result);

    Plaintext decrypted;
    dec.decrypt(result, decrypted);
    vector<double> res;
    encoder.decode(decrypted, res);

    cout << "Sum = " << res[0] << endl;
    return 0;
}
