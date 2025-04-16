// Exception handling and timing
#include "seal/seal.h"
#include <iostream>
#include <chrono>

using namespace std;
using namespace seal;

int main() {
    try {
        auto start = chrono::high_resolution_clock::now();

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

        double scale = pow(2.0, 40);
        Plaintext pt1, pt2;
        encoder.encode(4.2, scale, pt1);
        encoder.encode(1.8, scale, pt2);

        Ciphertext ct1, ct2;
        encryptor.encrypt(pt1, ct1);
        encryptor.encrypt(pt2, ct2);

        Ciphertext ct_result;
        evaluator.add(ct1, ct2, ct_result);

        Plaintext pt_result;
        decryptor.decrypt(ct_result, pt_result);
        vector<double> decoded;
        encoder.decode(pt_result, decoded);

        auto end = chrono::high_resolution_clock::now();
        cout << "Sum: " << decoded[0] << endl;
        cout << "⏱️ Time taken: " << chrono::duration<double>(end - start).count() << "s" << endl;
    } catch (const exception &e) {
        cerr << "Runtime error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
