#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main()
{
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    
    double scale = pow(2.0, 40);

    // Create SEAL context
    SEALContext context(parms);
    //print_parameters(context);
    cout << endl;

    // Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    // Create encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Create CKKS encoder
    CKKSEncoder encoder(context);

    // Define input vectors
    vector<double> input1{ 1.1, 2.2, 3.3, 4.4, 5.5 };
    vector<double> input2{ 2.2, 3.3, 4.4, 5.5, 6.6 };
    vector<double> expected_result(input1.size());
    for (size_t i = 0; i < input1.size(); i++) {
        expected_result[i] = input1[i] + input2[i];
    }

    // Print input vectors
    cout << "Input vector 1: ";
    for (auto val : input1) {
        cout << val << " ";
    }
    cout << endl;

    cout << "Input vector 2: ";
    for (auto val : input2) {
        cout << val << " ";
    }
    cout << endl;

    // Encode and encrypt the first vector
    Plaintext plain1;
    encoder.encode(input1, scale, plain1);
    Ciphertext encrypted1;
    encryptor.encrypt(plain1, encrypted1);

    // Encode and encrypt the second vector
    Plaintext plain2;
    encoder.encode(input2, scale, plain2);
    Ciphertext encrypted2;
    encryptor.encrypt(plain2, encrypted2);

    // Perform homomorphic addition
    Ciphertext encrypted_result;
    evaluator.add(encrypted1, encrypted2, encrypted_result);

    // Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    // Print the results
    cout << "\nExpected result: ";
    for (auto val : expected_result) {
        cout << val << " ";
    }
    cout << endl;

    cout << "Computed result: ";
    for (auto val : result) {
        cout << val << " ";
    }
    cout << endl;

    // Calculate and print the difference
    cout << "\nDifferences between expected and computed results:" << endl;
    for (size_t i = 0; i < result.size(); i++) {
        cout << "Element " << i << ": " << abs(result[i] - expected_result[i]) << endl;
    }

    return 0;
}