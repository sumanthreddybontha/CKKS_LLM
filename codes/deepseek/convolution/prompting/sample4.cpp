// Adds more than two values
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

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    vector<double> values = {2.0, 3.0, 4.0}; // 2 + 3 + 4 = 9
    Ciphertext total;

    for (size_t i = 0; i < values.size(); ++i) {
        Plaintext pt;
        encoder.encode(values[i], scale, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);
        if (i == 0)
            total = ct;
        else
            evaluator.add_inplace(total, ct);
    }

    Plaintext result_pt;
    decryptor.decrypt(total, result_pt);
    vector<double> result;
    encoder.decode(result_pt, result);

    cout << "Decrypted result: " << result[0] << endl;
    return 0;
}
