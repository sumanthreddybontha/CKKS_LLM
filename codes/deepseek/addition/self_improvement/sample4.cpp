// Function-based modular addition
#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

double encrypted_addition(double a, double b, double scale, SEALContext context,
                          Encryptor& encryptor, Decryptor& decryptor, CKKSEncoder& encoder, Evaluator& evaluator) {
    Plaintext p1, p2;
    encoder.encode(a, scale, p1);
    encoder.encode(b, scale, p2);

    Ciphertext c1, c2;
    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    Ciphertext sum;
    evaluator.add(c1, c2, sum);

    Plaintext decrypted;
    decryptor.decrypt(sum, decrypted);
    vector<double> result;
    encoder.decode(decrypted, result);

    return result[0];
}

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, { 60, 40, 40, 60 }));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    double result = encrypted_addition(6.6, 3.3, pow(2.0, 40), context, encryptor, decryptor, encoder, evaluator);
    cout << "Encrypted sum: " << result << endl;

    return 0;
}
