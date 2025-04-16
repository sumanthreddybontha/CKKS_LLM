#include "seal/seal.h"
#include <iostream>
using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 60}));

    SEALContext context(parms);
    CKKSEncoder encoder(context);
    KeyGenerator keygen(context);
    Encryptor enc(context, keygen.public_key());
    Decryptor dec(context, keygen.secret_key());
    Evaluator evaluator(context);

    double scale = pow(2.0, 40);
    vector<double> x = {10.0}, y = {20.0};
    Plaintext px, py;
    encoder.encode(x, scale, px);
    encoder.encode(y, scale, py);

    Ciphertext cx, cy;
    enc.encrypt(px, cx);
    enc.encrypt(py, cy);

    Ciphertext result;
    evaluator.add(cx, cy, result);

    Plaintext pres;
    dec.decrypt(result, pres);
    vector<double> decoded;
    encoder.decode(pres, decoded);

    cout << "Decrypted sum: " << decoded[0] << endl;
}
