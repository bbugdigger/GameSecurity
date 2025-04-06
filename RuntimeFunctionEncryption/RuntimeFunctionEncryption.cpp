#include <iostream>
#include <windows.h>
#include <vector>
#include <functional>
#include <algorithm>

void xor_crypt(uint8_t* data, size_t size, const uint8_t* key, size_t key_size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= key[i % key_size];
    }
}

// Memory page manipulation utilities
class MemoryProtector {
public:
    static bool protect(void* address, size_t size, DWORD protection) {
        DWORD oldProtect;
        return VirtualProtect(address, size, protection, &oldProtect);
    }

    static bool unprotect(void* address, size_t size) {
        return protect(address, size, PAGE_EXECUTE_READWRITE);
    }
};

// Encrypted function wrapper
template<typename Func>
class EncryptedFunction {
public:
    EncryptedFunction(Func* func, size_t size, const std::vector<uint8_t>& key)
        : m_func(func), m_size(size), m_key(key), m_encrypted(size) {

        // Make a copy of the original function
        std::copy_n(reinterpret_cast<uint8_t*>(func), size, m_encrypted.data());

        // Encrypt the original in memory
        encrypt();
    }

    // Call operator that decrypts, executes, then re-encrypts
    template<typename... Args>
    auto operator()(Args&&... args) {
        decrypt();

        // Execute the function
        auto result = std::invoke(m_func, std::forward<Args>(args)...);

        encrypt();
        return result;
    }

private:
    void encrypt() {
        MemoryProtector::unprotect(m_func, m_size);
        xor_crypt(reinterpret_cast<uint8_t*>(m_func), m_size, m_key.data(), m_key.size());
        MemoryProtector::protect(m_func, m_size, PAGE_EXECUTE_READ);
    }

    void decrypt() {
        MemoryProtector::unprotect(m_func, m_size);
        xor_crypt(reinterpret_cast<uint8_t*>(m_func), m_size, m_key.data(), m_key.size());
        MemoryProtector::protect(m_func, m_size, PAGE_EXECUTE_READ);
    }

    Func* m_func;
    size_t m_size;
    std::vector<uint8_t> m_key;
    std::vector<uint8_t> m_encrypted;
};

// Example function to protect
int __declspec(noinline) sensitive_function(int a, int b) {
    printf("Sensitive function executed!\n");
    return a + b;
}

// Helper to get function size (simplified - in real use, you'd need a better way)
size_t estimate_function_size(void* func) {
    // This is a simplified approach - in production you'd need:
    // 1. A more reliable way to determine function size (debug info, section boundaries, etc.)
    // 2. Or manually specify sizes for each function

    // For demo purposes, we'll use a fixed size
    return 128;
}

int main() {
    std::vector<uint8_t> key = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };

    // Create encrypted function wrapper
    auto func_size = estimate_function_size(reinterpret_cast<void*>(sensitive_function));
    EncryptedFunction encrypted_sensitive(&sensitive_function, func_size, key);

    // Call the function through the encrypted wrapper
    printf("Calling encrypted function...\n");
    int result = encrypted_sensitive(5, 3);
    printf("Result: %d\n", result);

    // The function is now encrypted again in memory

    return 0;
}