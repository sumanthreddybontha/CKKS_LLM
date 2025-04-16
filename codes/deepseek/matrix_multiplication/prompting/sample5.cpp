#include "seal/seal.h"
#include <vector>
#include <iostream>
#include <chrono>
#include <cmath>

#if defined(_WIN32)
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/resource.h>
#endif

using namespace std;
using namespace seal;

// ✅ Cross-platform memory usage in MB
double get_memory_usage_mb() {
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS info;
    GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info));
    return static_cast<double>(info.WorkingSetSize) / (1024 * 1024);
#else
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return static_cast<double>(usage.ru_maxrss) / 1024.0;
#endif
}

void print_memory_usage(const string& label) {
    cout << "[MEM] " << label << ": " << get_memory_usage_mb() << " MB" << endl;
}

// ✅ Print SEAL parameters (was missing)
void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "\n/ Encryption parameters:\n";
    cout << "| scheme: CKKS" << endl;
    cout << "| poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "| coeff_modulus size: "
         << context_data.total_coeff_modulus_bit_count() << " bits" << endl << endl;
}

// ✅ Chunked matrix multiplication using CKKS
void encrypted_matrix_multiply(
    const vector<vector<double>>& A,
    const vector<vector<double>>& B,
    size_t chunk_size
) {
    size_t rows = A.size();
    size_t cols = B[0].size();
    size_t inner = B.size(); // A[0].size() == B.size()

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 40, 40}));

    SEALContext context(parms);
    print_parameters(context);

    double scale = pow(2.0, 30);

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    vector<vector<double>> result(rows, vector<double>(cols, 0.0));
    size_t num_chunks = (inner + chunk_size - 1) / chunk_size;

    print_memory_usage("Before encryption");

    // Encrypt A's rows
    vector<Ciphertext> enc_A_rows(rows);
    for (size_t i = 0; i < rows; ++i) {
        Plaintext plain;
        encoder.encode(A[i], scale, plain);
        encryptor.encrypt(plain, enc_A_rows[i]);
    }

    print_memory_usage("After encryption");

    for (size_t j = 0; j < cols; ++j) {
        vector<double> col(inner);
        for (size_t k = 0; k < inner; ++k)
            col[k] = B[k][j];

        for (size_t i = 0; i < rows; ++i) {
            Ciphertext sum;
            bool initialized = false;

            for (size_t chunk = 0; chunk < num_chunks; ++chunk) {
                size_t start = chunk * chunk_size;
                size_t end = min(start + chunk_size, inner);
                vector<double> chunk_vec(inner, 0.0);
                for (size_t k = start; k < end; ++k) {
                    chunk_vec[k] = col[k];
                }

                Plaintext plain_chunk;
                encoder.encode(chunk_vec, scale, plain_chunk);
                Ciphertext mult;
                evaluator.multiply_plain(enc_A_rows[i], plain_chunk, mult);

                if (initialized) {
                    evaluator.add_inplace(sum, mult);
                } else {
                    sum = mult;
                    initialized = true;
                }
            }

            Plaintext plain_result;
            decryptor.decrypt(sum, plain_result);
            vector<double> decoded;
            encoder.decode(plain_result, decoded);
            result[i][j] = accumulate(decoded.begin(), decoded.end(), 0.0);
        }
    }

    print_memory_usage("After multiplication");

    cout << "🔢 Result matrix:" << endl;
    for (const auto& row : result) {
        for (auto val : row)
            cout << val << "\t";
        cout << endl;
    }
}

int main() {
    vector<vector<double>> A = {
        {1, 2, 3, 4},
        {4, 3, 2, 1},
        {1, 3, 2, 4},
        {2, 4, 1, 3}
    };

    vector<vector<double>> B = {
        {4, 1, 2, 3},
        {3, 2, 1, 4},
        {2, 3, 4, 1},
        {1, 4, 3, 2}
    };

    size_t chunk_size = 2;
    encrypted_matrix_multiply(A, B, chunk_size);

    return 0;
}
