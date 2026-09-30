#include "rp_v1.h"

#include <cstring>

#include "rp_blowfish_table.h"
#include "rp_enc_table.h"

namespace games::iidx::security {
namespace {

struct Blowfish {
    uint32_t P[16 + 2];
    uint32_t S[4][256];
};

uint32_t blowfish_F(Blowfish *bf, uint32_t x) {
    const uint16_t d = x & 0x00FF;
    x >>= 8;
    const uint16_t c = x & 0x00FF;
    x >>= 8;
    const uint16_t b = x & 0x00FF;
    x >>= 8;
    const uint16_t a = x & 0x00FF;
    uint32_t y = bf->S[0][a] + bf->S[1][b];
    y = y ^ bf->S[2][c];
    y = y + bf->S[3][d];
    return y;
}

void blowfish_encrypt(Blowfish *bf, uint32_t *xl, uint32_t *xr) {
    uint32_t Xl = *xl;
    uint32_t Xr = *xr;
    for (short i = 0; i < 16; ++i) {
        Xl = Xl ^ bf->P[i];
        Xr = blowfish_F(bf, Xl) ^ Xr;
        const uint32_t temp = Xl;
        Xl = Xr;
        Xr = temp;
    }
    const uint32_t temp = Xl;
    Xl = Xr;
    Xr = temp;
    Xr = Xr ^ bf->P[16];
    Xl = Xl ^ bf->P[16 + 1];
    *xl = Xl;
    *xr = Xr;
}

void blowfish_init(Blowfish *bf, const uint8_t *key, size_t key_length) {
    int j = 0;
    for (int i = 0; i < 16 + 2; ++i) {
        uint32_t data = 0;
        for (int k = 0; k < 4; ++k) {
            data = (data << 8) | key[j];
            j = j + 1;
            if (j >= static_cast<int>(key_length)) {
                j = 0;
            }
        }
        bf->P[i] = bf->P[i] ^ data;
    }

    uint32_t datal = 0;
    uint32_t datar = 0;
    for (int i = 0; i < 16 + 2; i += 2) {
        blowfish_encrypt(bf, &datal, &datar);
        bf->P[i] = datal;
        bf->P[i + 1] = datar;
    }
    for (int i = 0; i < 4; ++i) {
        for (int j2 = 0; j2 < 256; j2 += 2) {
            blowfish_encrypt(bf, &datal, &datar);
            bf->S[i][j2] = datal;
            bf->S[i][j2 + 1] = datar;
        }
    }
}

void rp_blowfish_init(Blowfish *ctx, const uint8_t *key, uint32_t seed) {
    memcpy(ctx->S, security_rp_blowfish_table_custom_sbox, sizeof(ctx->S));
    memcpy(ctx->P, security_rp_blowfish_table_custom_pbox, sizeof(ctx->P));
    blowfish_init(ctx, &key[seed], 14);
}

int rp_blowfish_enc_sub(int a1) {
    int result = a1;
    if (a1 & 7) {
        result = a1 - (a1 & 7) + 8;
    }
    return result;
}

// Simplified path matching bemanitools when input != output and length == 8.
int rp_blowfish_enc(Blowfish *ctx, const uint8_t *input, uint8_t *output, int length) {
    const int padded = rp_blowfish_enc_sub(length);
    uint8_t block[8] {};
    memcpy(block, input, length < 8 ? length : 8);
    if (length < 8) {
        memset(block + length, 8 - length, 8 - length);
    }
    memcpy(output, block, 8);
    blowfish_encrypt(ctx, reinterpret_cast<uint32_t *>(output),
            reinterpret_cast<uint32_t *>(output) + 1);
    // bemanitools loops in 8-byte strides up to padded; for length 8 that is one block.
    (void) padded;
    return padded;
}

uint32_t mcode_len(const char mcode[8]) {
    uint32_t len = 0;
    while (len < 8 && mcode[len] != ' ') {
        len++;
    }
    return len;
}

void encode_8_to_6_reverse(const uint8_t *in, uint8_t *out) {
    out[0] = static_cast<uint8_t>(((in[7] - 0x20) << 2) | (((in[6] - 0x20) >> 4) & 0x03));
    out[1] = static_cast<uint8_t>(((in[6] - 0x20) << 4) | (((in[5] - 0x20) >> 2) & 0x0F));
    out[2] = static_cast<uint8_t>(((in[5] - 0x20) << 6) | ((in[4] - 0x20) & 0x3F));
    out[3] = static_cast<uint8_t>(((in[3] - 0x20) << 2) | (((in[2] - 0x20) >> 4) & 0x03));
    out[4] = static_cast<uint8_t>(((in[2] - 0x20) << 4) | (((in[1] - 0x20) >> 2) & 0x0F));
    out[5] = static_cast<uint8_t>(((in[1] - 0x20) << 6) | ((in[0] - 0x20) & 0x3F));
}

} // namespace

void rp_generate_signed_eeprom(
        const char boot_version[8],
        const uint32_t boot_seeds[3],
        const char plug_mcode[8],
        const uint8_t plug_id[10],
        RpEeprom *out) {
    uint8_t encryption_key[sizeof(security_rp_enc_table_key_base)];
    memcpy(encryption_key, security_rp_enc_table_key_base, sizeof(encryption_key));

    const uint32_t boot_version_len = mcode_len(boot_version);
    uint32_t idx = 0;
    for (uint32_t i = 0; i < sizeof(encryption_key); i++) {
        encryption_key[i] ^= static_cast<uint8_t>(boot_version[idx]);
        idx = (idx + 1) % boot_version_len;
    }

    const uint32_t seed =
            16 * (boot_seeds[2] + 16 * (boot_seeds[1] + 16 * boot_seeds[0]));
    uint8_t *enc_key_section1 = encryption_key;
    uint8_t *enc_key_section2 = encryption_key + 14;

    uint8_t data[32] {};
    data[0] = enc_key_section2[seed];
    data[1] = enc_key_section2[seed + 1];
    // plug_id layout: [0]=header, [1..8]=id, [9]=checksum — bemanitools SecurityId
    // uses id[7]..id[2] which are bytes 8..3 of the 10-byte blob (header at 0).
    data[2] = plug_id[8];
    data[3] = plug_id[7];
    data[4] = plug_id[6];
    data[5] = plug_id[5];
    data[6] = plug_id[4];
    data[7] = plug_id[3];

    Blowfish ctx {};
    rp_blowfish_init(&ctx, enc_key_section1, seed);
    rp_blowfish_enc(&ctx, data, &data[16], 8);

    for (uint8_t i = 0; i < sizeof(out->signature); i++) {
        out->signature[i] = data[i + 16] ^ data[i + 22];
    }
    encode_8_to_6_reverse(reinterpret_cast<const uint8_t *>(plug_mcode), out->packed_payload);
}

} // namespace games::iidx::security
