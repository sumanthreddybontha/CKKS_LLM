#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    GaloisKeys gal_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    // Encode both matrices A and B into slots
    vector<double> A = {1, 2, 3, 4}; // A = [1 2; 3 4]
    vector<double> B = {5, 6, 7, 8}; // B = [5 6; 7 8]

    Plaintext pA, pB;
    encoder.encode(A, scale, pA);
    encoder.encode(B, scale, pB);

    Ciphertext cA, cB;
    encryptor.encrypt(pA, cA);
    encryptor.encrypt(pB, cB);

    Ciphertext result;
    evaluator.multiply(cA, cB, result); // element-wise
    evaluator.rescale_to_next_inplace(result);

    Plaintext pResult;
    vector<double> decoded;
    decryptor.decrypt(result, pResult);
    encoder.decode(pResult, decoded);

    cout << "SIMD-style element-wise multiplication result:" << endl;
    for (auto &val : decoded) cout << val << " ";
    cout << endl;

    return 0;
}