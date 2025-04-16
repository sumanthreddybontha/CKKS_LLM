#include <seal/seal.h>
#include <vector>
#include <numeric>
#include <iostream>
#include <cmath>
#include <stdexcept>
using namespace seal;
using namespace std;

class NoiseManagedDotProduct {
    unique_ptr<SEALContext> context;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    double scale;

    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    unique_ptr<CKKSEncoder> encoder;

    void initialize_seal() {
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);

        // Compatible with scale = 2^30
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 30, 30, 60}));

        context = make_unique<SEALContext>(parms, true, sec_level_type::tc128);
        if (!context->parameters_set()) {
            throw runtime_error("Error: encryption parameters are not set correctly");
        }

        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);

        encryptor = make_unique<Encryptor>(*context, public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        encoder = make_unique<CKKSEncoder>(*context);

        scale = pow(2.0, 30);
    }

    void print_parameters(const Ciphertext& ciphertext, const string& label) {
        auto context_data = context->get_context_data(ciphertext.parms_id());
        cout << "[" << label << "] Scale: " << ciphertext.scale()
             << ", Modulus chain index: " << context_data->chain_index() << endl;
    }

public:
    NoiseManagedDotProduct() {
        try {
            initialize_seal();
        } catch (const exception& e) {
            cerr << "Initialization failed: " << e.what() << endl;
            throw;
        }
    }

    double compute(const vector<double>& vec1, const vector<double>& vec2) {
        if (vec1.size() != vec2.size()) {
            throw invalid_argument("Vectors must be the same size");
        }

        try {
            // Encode
            Plaintext plain1, plain2;
            encoder->encode(vec1, scale, plain1);
            encoder->encode(vec2, scale, plain2);

            // Encrypt
            Ciphertext encrypted1, encrypted2;
            encryptor->encrypt(plain1, encrypted1);
            encryptor->encrypt(plain2, encrypted2);

            print_parameters(encrypted1, "After encryption");

            // Multiply directly, assuming both at same level & scale
            evaluator->multiply_inplace(encrypted1, encrypted2);
            evaluator->relinearize_inplace(encrypted1, relin_keys);
            evaluator->rescale_to_next_inplace(encrypted1);

            print_parameters(encrypted1, "After multiplication");

            // Decrypt and decode
            Plaintext plain_result;
            decryptor->decrypt(encrypted1, plain_result);

            vector<double> result;
            encoder->decode(plain_result, result);

            return accumulate(result.begin(), result.end(), 0.0);
        } catch (const exception& e) {
            cerr << "Computation error: " << e.what() << endl;
            throw;
        }
    }

    void print_parameters() const {
        auto& context_data = *context->first_context_data();
        cout << "Current parameters:\n"
             << "  Poly modulus degree: " << context_data.parms().poly_modulus_degree() << "\n"
             << "  Scale: " << scale << "\n"
             << "  Modulus chain count: " << context_data.chain_index() + 1 << endl;
    }
};

int main() {
    try {
        NoiseManagedDotProduct dp;

        vector<double> vec1 = {1.0, 2.0, 3.0, 4.0};
        vector<double> vec2 = {5.0, 6.0, 7.0, 8.0};

        dp.print_parameters();
        double result = dp.compute(vec1, vec2);

        cout << "Dot product result: " << result << endl;
        cout << "Expected result: " << inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0.0) << endl;

    } catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
