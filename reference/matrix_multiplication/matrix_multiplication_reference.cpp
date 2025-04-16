#include "openfhe.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace lbcrypto;

int main() {
    // Step 1: CKKS parameters setup
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(3);
    params.SetScalingModSize(50);
    params.SetScalingTechnique(FLEXIBLEAUTO);
    params.SetBatchSize(4);  // Enough to hold 2-element vectors

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // Step 2: Key Generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Step 3: Define 2x2 matrices
    vector<vector<double>> matA = {{1.0, 2.0}, {3.0, 4.0}};
    vector<vector<double>> matB = {{5.0, 6.0}, {7.0, 8.0}};

    // Step 4: Transpose matB to access columns
    vector<vector<double>> matB_T(2, vector<double>(2));
    for (int i = 0; i < 2; ++i)
        for (int j = 0; j < 2; ++j)
            matB_T[j][i] = matB[i][j];

    // Step 5: Encrypt rows of matA
    vector<Ciphertext<DCRTPoly>> encryptedA;
    for (const auto& row : matA) {
        Plaintext pt = cc->MakeCKKSPackedPlaintext(row);
        encryptedA.push_back(cc->Encrypt(keys.publicKey, pt));
    }

    // Encrypt columns of matB_T
    vector<Ciphertext<DCRTPoly>> encryptedB;
    for (const auto& col : matB_T) {
        Plaintext pt = cc->MakeCKKSPackedPlaintext(col);
        encryptedB.push_back(cc->Encrypt(keys.publicKey, pt));
    }

    // Step 6: Homomorphic matrix multiplication (dot products)
    vector<vector<Ciphertext<DCRTPoly>>> encryptedResult(2, vector<Ciphertext<DCRTPoly>>(2));

    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            auto mult = cc->EvalMult(encryptedA[i], encryptedB[j]);
            encryptedResult[i][j] = mult;
        }
    }

    // Step 7: Decrypt and print result matrix
    cout << "Decrypted matrix multiplication result:" << endl;
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            Plaintext pt;
            cc->Decrypt(keys.secretKey, encryptedResult[i][j], &pt);
            pt->SetLength(2);
            auto vals = pt->GetRealPackedValue();
            cout << vals[0] << "\t";  // First slot = dot product
        }
        cout << endl;
    }

    return 0;
}
