#include "openfhe.h"
#include <iostream>
#include <vector>
#include <random>
#include <iomanip>

using namespace std;
using namespace lbcrypto;

// Utility to generate random floating-point number
double random_double(double min, double max) {
    return min + (max - min) * (rand() / (double)RAND_MAX);
}

int main() {
    // Step 1: CKKS context setup
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(4);
    params.SetScalingModSize(50);
    params.SetScalingTechnique(FLEXIBLEAUTO);
    params.SetBatchSize(9); // For a 3x3 kernel

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // Step 2: Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    // Step 3: Generate 5x5 image and 3x3 kernel with bias
    const int image_size = 5;
    const int kernel_size = 3;
    const int output_size = image_size - kernel_size + 1;

    vector<vector<double>> image(image_size, vector<double>(image_size));
    vector<vector<double>> kernel(kernel_size, vector<double>(kernel_size));
    double bias = random_double(-1.0, 1.0);

    srand(time(0));
    cout << "Original Image:\n";
    for (int i = 0; i < image_size; i++) {
        for (int j = 0; j < image_size; j++) {
            image[i][j] = random_double(0.0, 10.0);
            cout << fixed << setprecision(2) << image[i][j] << "\t";
        }
        cout << endl;
    }

    cout << "\nKernel:\n";
    vector<double> kernel_flat;
    for (int i = 0; i < kernel_size; i++) {
        for (int j = 0; j < kernel_size; j++) {
            kernel[i][j] = random_double(-1.0, 1.0);
            kernel_flat.push_back(kernel[i][j]);
            cout << fixed << setprecision(2) << kernel[i][j] << "\t";
        }
        cout << endl;
    }

    cout << "\nBias: " << bias << endl;

    // Step 4: Encrypt image rows
    vector<Ciphertext<DCRTPoly>> encrypted_rows;
    for (const auto& row : image) {
        Plaintext pt = cc->MakeCKKSPackedPlaintext(row);
        encrypted_rows.push_back(cc->Encrypt(keys.publicKey, pt));
    }

    // Step 5: Encrypt flattened kernel and bias
    Plaintext pt_kernel = cc->MakeCKKSPackedPlaintext(kernel_flat);
    auto encrypted_kernel = cc->Encrypt(keys.publicKey, pt_kernel);

    Plaintext pt_bias = cc->MakeCKKSPackedPlaintext({bias});
    auto encrypted_bias = cc->Encrypt(keys.publicKey, pt_bias);

    // Step 6: Perform convolution (dot product of window and kernel)
    vector<vector<Ciphertext<DCRTPoly>>> encrypted_result(output_size, vector<Ciphertext<DCRTPoly>>(output_size));

    for (int i = 0; i < output_size; i++) {
        for (int j = 0; j < output_size; j++) {
            vector<double> window_flat;

            for (int ki = 0; ki < kernel_size; ki++) {
                vector<double> temp = {};
                for (int kj = 0; kj < kernel_size; kj++) {
                    temp.push_back(image[i + ki][j + kj]);
                }
                window_flat.insert(window_flat.end(), temp.begin(), temp.end());
            }

            Plaintext pt_window = cc->MakeCKKSPackedPlaintext(window_flat);
            auto encrypted_window = cc->Encrypt(keys.publicKey, pt_window);

            auto mult = cc->EvalMult(encrypted_window, encrypted_kernel);
            auto result = cc->EvalAdd(mult, encrypted_bias);
            encrypted_result[i][j] = result;
        }
    }

    // Step 7: Decrypt and print result
    cout << "\nDecrypted Convolution Result:\n";
    for (int i = 0; i < output_size; i++) {
        for (int j = 0; j < output_size; j++) {
            Plaintext pt;
            cc->Decrypt(keys.secretKey, encrypted_result[i][j], &pt);
            pt->SetLength(1);
            cout << fixed << setprecision(2) << pt->GetRealPackedValue()[0] << "\t";
        }
        cout << endl;
    }

    return 0;
}
