//Guided vector addition with comments from retrieved guide
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));

    SEALContext context(parms);
    double scale = pow(2.0, 40);

    KeyGenerator keygen(context);
    PublicKey pub;
    keygen.create_public_key(pub);
    SecretKey sec = keygen.secret_key();

    Encryptor encryptor(context, pub);
    Decryptor decryptor(context, sec);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    vector<double> x = {1.1}, y = {2.2};
    Plaintext p1, p2;
    encoder.encode(x, scale, p1);
    encoder.encode(y, scale, p2);

    Ciphertext c1, c2;
    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    Ciphertext result;
    evaluator.add(c1, c2, result);

    Plaintext final;
    decryptor.decrypt(result, final);
    vector<double> out;
    encoder.decode(final, out);

    cout << "CKKS addition: " << out[0] << endl;
    return 0;
}
