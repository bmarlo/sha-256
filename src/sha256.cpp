#include "marlo/sha256.hpp"
#include <array>

namespace marlo {

sha256::sha256()
    : _state{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}, _msglen(0)
{
    _hash.reserve(sha256::hash_size + sha256::block_size);
    _hash.resize(sha256::hash_size);
}

sha256& sha256::clear() noexcept
{
    _state[0] = 0x6a09e667;
    _state[1] = 0xbb67ae85;
    _state[2] = 0x3c6ef372;
    _state[3] = 0xa54ff53a;
    _state[4] = 0x510e527f;
    _state[5] = 0x9b05688c;
    _state[6] = 0x1f83d9ab;
    _state[7] = 0x5be0cd19;
    _msglen = 0;
    _hash.resize(sha256::hash_size);
    return *this;
}

constexpr std::array<std::uint32_t, 64> magic_table = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

template<typename fn_t>
void hash_impl(std::uint32_t state[8], std::size_t blocks, fn_t get_data)
{
    auto alice = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (~x & z);
    };

    auto bob = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    };

    auto rotr = [](std::uint32_t val, std::uint8_t shifts) {
        return (val >> shifts) | (val << (32 - shifts));
    };

    auto charlie = [&](std::uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    };

    auto dave = [&](std::uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    };

    auto eve = [&](std::uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    };

    auto mallory = [&](std::uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    };

    while (blocks--) {
        std::array<std::uint32_t, 64> words;
        get_data(words, 16);
        for (std::size_t i = 16; i < 64; i++) {
            auto val = mallory(words[i - 2]);
            val += words[i - 7];
            val += eve(words[i - 15]);
            val += words[i - 16];
            words[i] = val;
        }

        std::uint32_t tmp[8];
        for (std::size_t i = 0; i < 8; i++) {
            tmp[i] = state[i];
        }

        for (std::size_t i = 0; i < 64; i++) {
            auto foo = tmp[7];
            foo += dave(tmp[4]);
            foo += alice(tmp[4], tmp[5], tmp[6]);
            foo += magic_table[i] + words[i];

            auto bar = charlie(tmp[0]);
            bar += bob(tmp[0], tmp[1], tmp[2]);

            tmp[7] = tmp[6];
            tmp[6] = tmp[5];
            tmp[5] = tmp[4];
            tmp[4] = tmp[3] + foo;
            tmp[3] = tmp[2];
            tmp[2] = tmp[1];
            tmp[1] = tmp[0];
            tmp[0] = foo + bar;
        }

        for (std::size_t i = 0; i < 8; i++) {
            state[i] += tmp[i];
        }
    }
}

sha256& sha256::update(const std::uint8_t* data, std::size_t size) noexcept
{
    _msglen += size;
    const std::uint8_t* src;
    auto get_data = [&](auto& words, std::size_t count) {
        for (std::size_t k = 0; k < count; k++) {
            std::uint32_t val = 0;
            val |= *src++ << 24;
            val |= *src++ << 16;
            val |= *src++ << 8;
            val |= *src++;
            words[k] = val;
        }
    };

    if (_hash.size() > sha256::hash_size) {    // consume buffered data
        auto space = _hash.capacity() - _hash.size();
        std::size_t copied = size > space ? space : size;
        std::string_view tmp(reinterpret_cast<const char*>(data), copied);
        _hash.append(tmp);
        data += copied;
        size -= copied;
        if (copied == space) {      // got a full block
            src = reinterpret_cast<const std::uint8_t*>(&_hash[sha256::hash_size]);
            hash_impl(_state, 1, get_data);
            _hash.resize(sha256::hash_size);
        }
    }

    if (auto rem = size % sha256::block_size) {
        std::string_view tmp(reinterpret_cast<const char*>(data + size - rem), rem);
        _hash.append(tmp);
    }

    src = data;
    hash_impl(_state, size / sha256::block_size, get_data);
    return *this;
}

const std::string& sha256::finalize(const std::uint8_t* data, std::size_t size, std::uint8_t* dst) noexcept
{
    _msglen += size;
    if (_hash.size() > sha256::hash_size) {
        auto space = _hash.capacity() - _hash.size();
        std::size_t copied = size > space ? space : size;
        std::string_view tmp(reinterpret_cast<const char*>(data), copied);
        _hash.append(tmp);
        if (copied == space) {
            data += copied;
            size -= copied;
            auto src = reinterpret_cast<const std::uint8_t*>(&_hash[sha256::hash_size]);
            auto get_data = [&](auto& words, std::size_t count) {
                for (std::size_t k = 0; k < count; k++) {
                    std::uint32_t val = 0;
                    val |= *src++ << 24;
                    val |= *src++ << 16;
                    val |= *src++ << 8;
                    val |= *src++;
                    words[k] = val;
                }
            };
            hash_impl(_state, 1, get_data);
            _hash.resize(sha256::hash_size);
        } else {
            data = reinterpret_cast<const std::uint8_t*>(&_hash[sha256::hash_size]);
            size = _hash.size() - sha256::hash_size;
        }
    }

    std::array<std::uint8_t, 72> padding {};
    std::size_t rem = size % sha256::block_size;
    std::size_t pads = rem > 56 ? 120 - rem : 56 - rem;     // [1, 64] bytes
    pads = !pads ? sha256::block_size : pads;

    padding[0] = 0x80;
    std::size_t shifts = 56;
    std::uint64_t bit_size = _msglen * 8;
    for (std::size_t i = 0; i < 8; i++) {   // 0xffeebbaa99881100 -> ffeebbaa99881100
        padding[pads + i] = static_cast<std::uint8_t>(bit_size >> shifts);
        shifts -= 8;
    }

    std::size_t offset = 0;
    auto get_data = [&](auto& words, std::size_t count) {
        for (std::size_t k = 0; k < count; k++) {
            std::uint32_t val = 0;
            if (offset + 3 < size) {
                val |= data[offset++] << 24;
                val |= data[offset++] << 16;
                val |= data[offset++] << 8;
                val |= data[offset++];
            } else {
                const std::uint8_t* src;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 24;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 16;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 8;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src;
            }
            words[k] = val;
        }
    };

    std::size_t blocks = (size + pads + 8) / sha256::block_size;
    hash_impl(_state, blocks, get_data);

    static constexpr char hex_table[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    offset = 0;
    for (std::size_t i = 0; i < 8; i++) {
        shifts = 24;
        auto word = _state[i];
        for (std::size_t k = 0; k < 4; k++) {
            auto val = static_cast<std::uint8_t>(word >> shifts);
            if (dst) {
                *dst++ = val;
            }
            _hash[offset++] = static_cast<char>(hex_table[val >> 4]);
            _hash[offset++] = static_cast<char>(hex_table[val & 0x0f]);
            shifts -= 8;
        }
    }

    clear();
    return _hash;
}

}
