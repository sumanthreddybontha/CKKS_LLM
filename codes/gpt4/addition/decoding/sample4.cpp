#include "seal/seal.h"
#include <iostream>
using namespace seal;
using namespace std;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {50, 40, 50}));
    SEALContext context(parms);
    CKKSEncoder encoder(context);

    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, keygen.secret_key());
    Evaluator evaluator(context);

    double scale = pow(2.0, 30);
    Plaintext p1, p2;
    encoder.encode(6.0, scale, p1);
    encoder.encode(7.0, scale, p2);

    Ciphertext c1, c2;
    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    Ciphertext cres;
    evaluator.add(c1, c2, cres);

    Plaintext pres;
    decryptor.decrypt(cres, pres);
    vector<double> res;
    encoder.decode(pres, res);
    cout << "Sum: " << res[0] << endl;
}
