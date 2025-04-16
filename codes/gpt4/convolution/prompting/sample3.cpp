// Uses relinearization after addition
#include "seal/seal.h"
#include <iostream>

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
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    vector<double> input1 = {2.0}, input2 = {5.0};
    Plaintext p1, p2;
    encoder.encode(input1, scale, p1);
    encoder.encode(input2, scale, p2);

    Ciphertext c1, c2;
    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    Ciphertext sum;
    evaluator.add(c1, c2, sum);
    evaluator.relinearize_inplace(sum, relin_keys);

    Plaintext result_pt;
    decryptor.decrypt(sum, result_pt);
    vector<double> result;
    encoder.decode(result_pt, result);

    cout << "Decrypted result: " << result[0] << endl;
    return 0;
}
