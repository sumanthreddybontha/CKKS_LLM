#include <iostream>
#include <fstream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // CKKS setup
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(16384);
    parms.set_coeff_modulus(CoeffModulus::Create(16384, {60, 40, 40, 60}));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // Prepare crypto components
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Read from file
    ifstream fin("vectors.txt");
    if (!fin) {
        cerr << "Could not open vectors.txt" << endl;
        return 1;
    }

    size_t num_vectors;
    fin >> num_vectors;
    vector<vector<double>> vectors;
    for (size_t i = 0; i < num_vectors; i++) {
        size_t vec_size;
        fin >> vec_size;
        vector<double> vec(vec_size);
        for (auto &x : vec) fin >> x;
        vectors.push_back(vec);
    }

    // Process vector pairs
    double scale = pow(2.0, 50);
    for (size_t i = 0; i < vectors.size(); i += 2) {
        if (i+1 >= vectors.size()) break;

        vector<double> vec1 = vectors[i];
        vector<double> vec2 = vectors[i+1];
        vec1.resize(slot_count, 0.0);
        vec2.resize(slot_count, 0.0);

        // Encrypt
        Plaintext plain1, plain2;
        encoder.encode(vec1, scale, plain1);
        encoder.encode(vec2, scale, plain2);
        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);

        // Compute
        evaluator.multiply_inplace(encrypted1, encrypted2);
        evaluator.relinearize_inplace(encrypted1, relin_keys);
        evaluator.rescale_to_next_inplace(encrypted1);

        // Sum
        Ciphertext result = encrypted1;
        for (size_t j = 1; j < slot_count; j *= 2) {
            Ciphertext rotated;
            evaluator.rotate_vector(result, j, galois_keys, rotated);
            evaluator.add_inplace(result, rotated);
        }

        // Decrypt
        Plaintext plain_result;
        decryptor.decrypt(result, plain_result);
        vector<double> decoded;
        encoder.decode(plain_result, decoded);

        cout << "Pair " << i/2 << " result: " << decoded[0] << endl;
    }

    return 0;
}