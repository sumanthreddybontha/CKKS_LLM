#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // === Encryption Parameters (from KG: poly_modulus_degree = power of 2, coeff_modulus = 60-bit primes)
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    // print_parameters(context);
    cout << endl;

    // === Key Generation (Core Operations: Encrypt/Decrypt, Relinearize, Galois Automorphisms)
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // === Encoding Setup (KG: FractionalEncoder / SIMD style CRT batching)
    double scale = pow(2.0, 40);

    // === Simulated Input Retrieval (RAG Style): Dot product between user query embedding and document embedding
    vector<double> query_vec = {1.2, 0.8, -1.3, 2.1};
    vector<double> doc_vec   = {0.5, 1.1, -0.9, 2.0};

    Plaintext pt_query, pt_doc;
    encoder.encode(query_vec, scale, pt_query);
    encoder.encode(doc_vec, scale, pt_doc);

    Ciphertext ct_query, ct_doc;
    encryptor.encrypt(pt_query, ct_query);
    encryptor.encrypt(pt_doc, ct_doc);

    // === Dot Product (Multiply, Relinearize, Rescale)
    Ciphertext prod;
    evaluator.multiply(ct_query, ct_doc, prod);
    evaluator.relinearize_inplace(prod, relin_keys);
    evaluator.rescale_to_next_inplace(prod);

    // === Aggregation Using Galois Automorphisms (Sum vector into one slot)
    for (size_t i = 1; i < query_vec.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(prod, i, gal_keys, rotated);
        evaluator.add_inplace(prod, rotated);
    }

    // === Decode Result
    Plaintext pt_result;
    decryptor.decrypt(prod, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);

    cout << "🔢 Homomorphic Dot Product (approx): " << result[0] << endl;

    return 0;
}
