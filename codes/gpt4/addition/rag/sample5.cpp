//Structured from retrieved educational content
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40}));

    SEALContext context(parms);
    double scale = pow(2.0, 40);

    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    vector<double> input1 = {100.0}, input2 = {23.0};
    Plaintext pa, pb;
    encoder.encode(input1, scale, pa);
    encoder.encode(input2, scale, pb);

    Ciphertext ca, cb;
    encryptor.encrypt(pa, ca);
    encryptor.encrypt(pb, cb);

    Ciphertext result;
    evaluator.add(ca, cb, result);

    Plaintext final;
    decryptor.decrypt(result, final);
    vector<double> out;
    encoder.decode(final, out);

    cout << "Decoded RAG Sum: " << out[0] << endl;
    return 0;
}
