// Separate function to initialize context
#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

SEALContext create_ckks_context() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, { 60, 40, 40, 60 }));
    return SEALContext(parms);
}

int main() {
    SEALContext context = create_ckks_context();

    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    double scale = pow(2.0, 40);

    Plaintext pt1, pt2;
    encoder.encode(7.0, scale, pt1);
    encoder.encode(5.0, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    Ciphertext result;
    evaluator.add(ct1, ct2, result);

    Plaintext decrypted;
    decryptor.decrypt(result, decrypted);
    vector<double> decoded;
    encoder.decode(decrypted, decoded);

    cout << "Result: " << decoded[0] << endl;
    return 0;
}
