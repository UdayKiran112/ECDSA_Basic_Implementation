#include <bits/stdc++.h>
#include "Lib/arch.h"
#include "Lib/core.h"
#include "Lib/randapi.h"
#include "Lib/big_B256_56.h"
#include "Lib/ecp_SECP256K1.h"
#include "Lib/ecdh_SECP256K1.h"

using namespace std;
using namespace SECP256K1;

void generate_seed(octet &RAW, unsigned long seed)
{
    RAW.len = 100;
    RAW.val[0] = seed;
    RAW.val[1] = seed >> 8;
    RAW.val[2] = seed >> 16;
    RAW.val[3] = seed >> 24;
    random_device rd;
    for (int i = 4; i < 100; i++)
    {
        RAW.val[i] = rd() & 0xFF;
    }
}

int ecdsa_sign_verify(csprng *RNG)
{

    char priv[2 * EGS_SECP256K1], pub[2 * EFS_SECP256K1 + 1];

    octet privKey = {0, size(priv), priv};
    octet pubKey = {0, size(pub), pub};

    // Generate Key Pair
    if (ECP_KEY_PAIR_GENERATE(RNG, &privKey, &pubKey) != 0)
    {
        cout << "Key pair not generated" << endl;
        ;
        return 0;
    }

    // print private and public Key
    cout << "Private Key : ";
    OCT_output(&privKey);
    cout << endl;

    cout << "Public Key : ";
    OCT_output(&pubKey);
    cout << endl;

    // Validate Public Key
    int res = ECP_PUBLIC_KEY_VALIDATE(&pubKey);
    if (res != 0)
    {
        cout << "Invalid Public Key" << endl;
        return -1;
    }

    // Message to sign
    string msg = "Hello World!";
    octet Message;
    Message.len = msg.size();
    Message.max = msg.size();
    Message.val = new char[msg.size()];
    memcpy(Message.val, msg.c_str(), msg.size());

    // Print Message
    cout << "Message in hex : ";
    OCT_output(&Message);
    cout << endl;

    char h[32];
    octet hashed_message = {0, size(h), h};
    cout << hashed_message.len << endl;

    SPhash(MC_SHA2, 32, &hashed_message, &Message);

    cout << "Hash of the message is :";
    OCT_output(&hashed_message);
    cout << endl;

    // Sign the message
    char cs[EGS_SECP256K1], ds[EGS_SECP256K1];
    octet CS = {0, sizeof(cs), cs};
    octet DS = {0, sizeof(ds), ds};

    if (ECP_SP_DSA(32, RNG, nullptr, &privKey, &Message, &CS, &DS) != 0)
    {
        cout << "Signature failed" << endl;
        return -1;
    }

    // Display the signature
    cout << "Signature C: ";
    OCT_output(&CS);
    cout << "\nSignature D: ";
    OCT_output(&DS);
    cout << endl;

    // Verify the signature
    if (ECP_VP_DSA(32, &pubKey, &Message, &CS, &DS) != 0)
    {
        cout << "Verification failed" << endl;
        return -1;
    }
    cout << "Signature verified successfully!" << endl;
    return 0;
}

int main()
{
    unsigned long ran;
    octet RAW = {0, 100, new char[100]};
    csprng RNG;

    // Generate seed and initialize CSPRNG
    random_device rd;
    ran = static_cast<unsigned long>(time(nullptr)) ^ rd();
    generate_seed(RAW, ran);
    core::CREATE_CSPRNG(&RNG, &RAW);

    // Sign and verify using ECDSA
    if (ecdsa_sign_verify(&RNG) != 0)
    {
        cout << "ECDSA operation failed." << endl;
    }

    // Clean up
    core::KILL_CSPRNG(&RNG);
    delete[] RAW.val;

    return 0;
}
