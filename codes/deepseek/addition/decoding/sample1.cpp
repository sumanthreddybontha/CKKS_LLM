#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    SEALContext context(parms);

    double scale = pow(2.0, 40);
    KeyGenerator keygen(context);
    PublicKey pub; keygen.create_public_key(pub);
    SecretKey sec = keygen.secret_key();
    Encryptor encryptor(context, pub);
    Decryptor decryptor(context, sec);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    vector<double> a = {1.5}, b = {2.5};
    Plaintext pa, pb; encoder.encode(a, scale, pa); encoder.encode(b, scale, pb);
    Ciphertext ea, eb; encryptor.encrypt(pa, ea); encryptor.encrypt(pb, eb);

    Ciphertext result; evaluator.add(ea, eb, result);
    Plaintext pres; decryptor.decrypt(result, pres);
    vector<double> decoded; encoder.decode(pres, decoded);
    cout << "Decrypted result: " << decoded[0] << endl;
}
