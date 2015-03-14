#include "libtorrent/config.hpp"
#include "libtorrent/ed25519.hpp"

#ifndef ED25519_NO_SEED

#ifdef TORRENT_WINRT
#include <robuffer.h>
#include <wrl/client.h>
using namespace Windows::Security::Cryptography;
using namespace Windows::Storage::Streams;
using namespace Microsoft::WRL;
#elif defined _WIN32
#include <Windows.h>
#include <Wincrypt.h>
#else
#include <stdio.h>
#endif

int ed25519_create_seed(unsigned char *seed) {
#ifdef TORRENT_WINRT
    IBuffer^ seedBuffer = CryptographicBuffer::GenerateRandom(32);
    ComPtr<IBufferByteAccess> bufferByteAccess;
    reinterpret_cast<IInspectable*>(seedBuffer)->QueryInterface(IID_PPV_ARGS(&bufferByteAccess));
    bufferByteAccess->Buffer(&seed);
#elif defined _WIN32
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))  {
        return 1;
    }

    if (!CryptGenRandom(prov, 32, seed))  {
        CryptReleaseContext(prov, 0);
        return 1;
    }

    CryptReleaseContext(prov, 0);
#else
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        return 1;
    }

    fread(seed, 1, 32, f);
    fclose(f);
#endif

    return 0;
}

#endif

