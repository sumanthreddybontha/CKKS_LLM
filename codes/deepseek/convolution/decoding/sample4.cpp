#include <iostream>
#include <vector>
#include <sstream>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_vector(const vector<double>& vec, size_t print_size) {
    for (size_t i = 0; i < print_size; ++i) {
        cout << vec[i] << ((i != print_size - 1) ? ", " : "\n");
    }
}

int main() {
    cout << "Batch CKKS Convolution\n";

    // Configuration
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Key generation
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Create relinearization keys and deserialize manually
    Serializable<RelinKeys> relin_keys_serializable = keygen.create_relin_keys();
    stringstream relin_stream;
    relin_keys_serializable.save(relin_stream);

    RelinKeys relin_keys;
    relin_keys.load(context, relin_stream); // ✅ Correct for all SEAL versions

    // Setup crypto tools
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Input vectors
    vector<double> signal{1.0, 2.0, 3.0, 4.0};
    vector<double> kernel{0.5, 0.25, 0.125, 0.0625};
    signal.resize(slot_count, 0.0);
    kernel.resize(slot_count, 0.0);

    // Encode and encrypt
    Plaintext pt_signal, pt_kernel;
    double scale = pow(2.0, 40);
    encoder.encode(signal, scale, pt_signal);
    encoder.encode(kernel, scale, pt_kernel);

    Ciphertext ct_signal, ct_kernel;
    encryptor.encrypt(pt_signal, ct_signal);
    encryptor.encrypt(pt_kernel, ct_kernel);

    // Multiply, relinearize, rescale
    Ciphertext ct_result;
    evaluator.multiply(ct_signal, ct_kernel, ct_result);
    evaluator.relinearize_inplace(ct_result, relin_keys);
    evaluator.rescale_to_next_inplace(ct_result);

    // Decrypt and decode
    Plaintext pt_result;
    decryptor.decrypt(ct_result, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);

    // Compute expected result
    vector<double> expected;
    for (size_t i = 0; i < signal.size() + kernel.size() - 1; ++i) {
        double sum = 0.0;
        for (size_t j = 0; j < kernel.size(); ++j) {
            if (i >= j && (i - j) < signal.size()) {
                sum += signal[i - j] * kernel[j];
            }
        }
        expected.push_back(sum);
    }

    // Print output
    cout << "First 7 expected vs actual:\n";
    print_vector(expected, 7);
    print_vector(result, 7);

    return 0;
}
