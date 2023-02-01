#pragma once

#include <cstdint>
#include <string>

namespace marlo {

class sha256 {
public:
    sha256();

    sha256& clear() noexcept;
    sha256& update(std::string_view bytes) noexcept;
    sha256& update(const std::uint8_t* data, std::size_t size) noexcept;
    const std::string& finalize(std::string_view bytes, std::string& dst);
    const std::string& finalize(std::string_view bytes, std::uint8_t* dst = nullptr) noexcept;
    const std::string& finalize(const std::uint8_t* data, std::size_t size, std::string& dst);
    const std::string& finalize(const std::uint8_t* data, std::size_t size, std::uint8_t* dst = nullptr) noexcept;

    static std::string eval(std::string_view bytes);

    static constexpr std::size_t bit_size = 256;
    static constexpr std::size_t block_size = 64;
    static constexpr std::size_t hash_size = 64;

private:
    std::uint32_t _state[8];
    std::uint64_t _msglen;
    std::string _hash;
};

inline sha256& sha256::update(std::string_view bytes) noexcept
{
    return update(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
}

inline const std::string& sha256::finalize(std::string_view bytes, std::string& dst)
{
    auto old_size = dst.size();
    dst.resize(old_size + sha256::bit_size / 8);
    return finalize(bytes, reinterpret_cast<std::uint8_t*>(&dst[old_size]));
}

inline const std::string& sha256::finalize(std::string_view bytes, std::uint8_t* dst) noexcept
{
    return finalize(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), dst);
}

inline const std::string& sha256::finalize(const std::uint8_t* data, std::size_t size, std::string& dst)
{
    auto old_size = dst.size();
    dst.resize(old_size + sha256::bit_size / 8);
    return finalize(data, size, reinterpret_cast<std::uint8_t*>(&dst[old_size]));
}

inline std::string sha256::eval(std::string_view bytes)
{
    return sha256().finalize(bytes);
}

}
