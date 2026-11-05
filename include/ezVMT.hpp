#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <cstring>

namespace ezVMT {
    // 钩子操作标志
    constexpr uint32_t All_Hooks = 1 << 0; // 应用于所有钩子
    constexpr uint32_t NO_Module_Stomping = 1 << 1; // 不使用模块踩踏和 Data Cave，直接申请独立内存

    // 内存配置常量
    constexpr DWORD VMT_ALLOC_PROTECTION = PAGE_READWRITE;
    constexpr uint8_t DATA_CAVE_RESET_BYTE = 0x00; // Data Cave 恢复归零的目标字节值
    constexpr size_t VMT_META_COUNT = 2;           // 虚表前缀元数据指针数量（RTTI 和 Complete Object Locator）

    // 钩子创建/操作状态机
    enum class HookStatus : int {
        OK = 0,

        Unknown = -1,
        InvalidArgument = 1,
        AlreadyCreated,
        NotCreated,
        AlreadyEnabled,
        NotEnabled,
        InvalidModuleBase,
        InvalidVmt,
        InvalidFunction,
        VmtSizeFailed,
        IndexOutOfRange,
        MemoryAllocationFailed,
        MemoryProtectionFailed,
        DataCaveNotFound,
        PatternInvalid,
        PatternReadFailed,
        PatternMismatch,
        OutOfMemory
    };

    // 检查指定内存范围是否可读，不使用 SEH
    inline bool IsMemoryReadable(const void* address, size_t size) {
        if (size == 0) {
            return true;
        }
        if (!address) {
            return false;
        }

        uintptr_t start = reinterpret_cast<uintptr_t>(address);
        uintptr_t end = start + size;
        if (end < start) {
            return false;
        }

        uintptr_t current = start;
        while (current < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi)) == 0) {
                return false;
            }

            if (mbi.State != MEM_COMMIT) {
                return false;
            }

            if (mbi.Protect & PAGE_GUARD) {
                return false;
            }

            DWORD protect = mbi.Protect & 0xFF;
            if (protect == PAGE_NOACCESS || protect == PAGE_EXECUTE) {
                return false;
            }

            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd <= current) {
                return false;
            }

            current = regionEnd;
        }

        return true;
    }

    inline bool IsPatternSpace(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    inline bool IsHexChar(char c) {
        return (c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'F') ||
            (c >= 'a' && c <= 'f');
    }

    inline uint8_t HexCharToValue(char c) {
        if (c >= '0' && c <= '9') {
            return static_cast<uint8_t>(c - '0');
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<uint8_t>(c - 'A' + 10);
        }
        return static_cast<uint8_t>(c - 'a' + 10);
    }

    // 匹配函数头部机器码特征码。
    // 支持 "?" 和 "??" 两种通配符，例如：
    // "48 8B C4 41 54 48 83 EC ? 48 89 58 ? 48"
    inline HookStatus MatchBytePattern(const void* address, const char* pattern) {
        if (!address || !pattern) {
            return HookStatus::InvalidArgument;
        }

        const uint8_t* code = reinterpret_cast<const uint8_t*>(address);
        const char* p = pattern;
        size_t offset = 0;
        size_t tokenCount = 0;

        while (*p) {
            while (*p && IsPatternSpace(*p)) {
                ++p;
            }
            if (!*p) {
                break;
            }

            const char* tokenStart = p;
            while (*p && !IsPatternSpace(*p)) {
                ++p;
            }

            size_t tokenLength = static_cast<size_t>(p - tokenStart);
            bool isWildcard = false;
            uint8_t expectedValue = 0;

            if (tokenLength == 1 && tokenStart[0] == '?') {
                isWildcard = true;
            }
            else if (tokenLength == 2 && tokenStart[0] == '?' && tokenStart[1] == '?') {
                isWildcard = true;
            }
            else if (tokenLength == 2 &&
                IsHexChar(tokenStart[0]) &&
                IsHexChar(tokenStart[1])) {
                expectedValue = static_cast<uint8_t>(
                    (HexCharToValue(tokenStart[0]) << 4) |
                    HexCharToValue(tokenStart[1])
                    );
            }
            else {
                return HookStatus::PatternInvalid;
            }

            if (!IsMemoryReadable(code + offset, 1)) {
                return HookStatus::PatternReadFailed;
            }

            if (!isWildcard && code[offset] != expectedValue) {
                return HookStatus::PatternMismatch;
            }

            ++offset;
            ++tokenCount;
        }

        if (tokenCount == 0) {
            return HookStatus::PatternInvalid;
        }

        return HookStatus::OK;
    }

    // 内部结构体：保存 Hook 上下文信息
    struct HookEntry {
        void* detour;             // 自定义钩子函数的地址（作为主键）
        void*** classInstance;    // 类的实例地址（即 &vtable 指针）
        void** originalVmt;       // 原始虚函数表地址
        void** customVmt;         // 复制出的新虚函数表首地址（指向函数入口起始处）
        void* originalFunc;       // 原始函数地址
        size_t index;             // 挂钩的虚表索引
        size_t totalCount;        // 虚表函数总数量
        bool isEnabled;           // 当前是否已启用
        bool isAllocated;         // 标记内存是否为独立申请（非模块 Data Cave）
    };

    // 全局钩子记录列表
    inline std::vector<HookEntry> g_Hooks;

    // 检查候选 Data Cave 是否与已存在的 Hook 内存重叠
    inline bool IsDataCaveOverlap(uintptr_t start, size_t size) {
        uintptr_t end = start + size;
        for (const auto& entry : g_Hooks) {
            if (entry.customVmt && !entry.isAllocated) {
                uintptr_t usedStart = reinterpret_cast<uintptr_t>(&(entry.customVmt[-2]));
                uintptr_t usedEnd = usedStart + ((entry.totalCount + 2) * sizeof(void*));

                if (start < usedEnd && end > usedStart) {
                    return true;
                }
            }
        }
        return false;
    }

    // 获取模块的可执行代码内存范围
    inline void GetTextSectionRange(uintptr_t moduleBase, uintptr_t& outStart, uintptr_t& outEnd) {
        auto dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return;
        }

        auto ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
        if (!ntHeaders || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return;
        }

        outStart = moduleBase + ntHeaders->OptionalHeader.BaseOfCode;
        outEnd = outStart + ntHeaders->OptionalHeader.SizeOfCode;

        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                uintptr_t secStart = moduleBase + sectionHeader[i].VirtualAddress;
                uintptr_t secEnd = secStart + sectionHeader[i].Misc.VirtualSize;

                if (secStart < outStart) outStart = secStart;
                if (secEnd > outEnd) outEnd = secEnd;
            }
        }
    }

    // 动态计算虚函数表中的函数数量
    inline size_t GetVMTSizeDynamic(void** vmt) {
        static uintptr_t textStart = 0, textEnd = 0;
        if (!textStart) {
            GetTextSectionRange((uintptr_t)GetModuleHandleA(NULL), textStart, textEnd);
        }

        if (!textStart || !vmt) {
            return 0;
        }

        size_t count = 0;
        while (vmt[count]) {
            uintptr_t func = (uintptr_t)vmt[count];
            if (func < textStart || func >= textEnd) {
                break;
            }
            count++;
        }
        return count;
    }

    // 查找目标模块数据段中的空闲区域 (Data Cave)
    inline uintptr_t FindGameDataCave(uintptr_t moduleBase, size_t size) {
        auto dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }

        auto ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
        if (!ntHeaders || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(sectionHeader[i].Name, ".data", 5) == 0 ||
                memcmp(sectionHeader[i].Name, ".bss", 4) == 0) {

                uintptr_t sectionStart = moduleBase + sectionHeader[i].VirtualAddress;
                size_t sectionSize = sectionHeader[i].Misc.VirtualSize;

                size_t consecutiveZeroes = 0;
                for (size_t offset = sectionSize - 1; offset > 0; offset--) {
                    if (*(BYTE*)(sectionStart + offset) == 0x00) {
                        consecutiveZeroes++;
                        if (consecutiveZeroes >= size + 16) {
                            uintptr_t candidate = (sectionStart + offset + 15) & ~15;

                            if (IsDataCaveOverlap(candidate, size)) {
                                consecutiveZeroes = 0;
                                continue;
                            }

                            return candidate;
                        }
                    }
                    else {
                        consecutiveZeroes = 0;
                    }
                }
            }
        }
        return 0;
    }

    // 查找内部 Hook 条目辅助函数
    inline HookEntry* FindHookEntry(void* detour) {
        for (auto& entry : g_Hooks) {
            if (entry.detour == detour) {
                return &entry;
            }
        }
        return nullptr;
    }

    /**
     * @brief 创建一个 VMT Hook（基于模块数据段 Cave）
     * @param detour 自定义钩子函数的地址
     * @param classInstance 拥有虚表的实例指针
     * @param index 要挂钩的虚表索引
     * @param outOriginal [可选输出] 接收原函数指针
     * @param flags 钩子操作标志
     * @param expectedBytes [可选] 目标函数头部机器码特征码，支持 "?" 和 "??" 通配符
     * @return 返回 HookStatus 状态枚举
     */
    inline HookStatus CreateHook(
        void* detour,
        void* classInstance,
        size_t index,
        void** outOriginal = nullptr,
        uint32_t flags = 0,
        const char* expectedBytes = nullptr
    ) {
        if (!detour || !classInstance) {
            return HookStatus::InvalidArgument;
        }

        if (FindHookEntry(detour) != nullptr) {
            return HookStatus::AlreadyCreated;
        }

        void*** pInstance = reinterpret_cast<void***>(classInstance);
        void** originalVmt = *pInstance;

        if (!originalVmt) {
            return HookStatus::InvalidVmt;
        }

        size_t totalCount = GetVMTSizeDynamic(originalVmt);
        if (totalCount == 0) {
            return HookStatus::VmtSizeFailed;
        }

        if (index >= totalCount) {
            return HookStatus::IndexOutOfRange;
        }

        void* originalFunc = originalVmt[index];
        if (!originalFunc) {
            return HookStatus::InvalidFunction;
        }

        if (expectedBytes) {
            HookStatus patternStatus = MatchBytePattern(originalFunc, expectedBytes);
            if (patternStatus != HookStatus::OK) {
                return patternStatus;
            }
        }

        size_t totalVmtBytes = (totalCount + 2) * sizeof(void*);
        void** shadowVMTBuffer = nullptr;
        bool isAllocated = false;

        if (flags & NO_Module_Stomping) {
            shadowVMTBuffer = reinterpret_cast<void**>(
                VirtualAlloc(nullptr, totalVmtBytes, MEM_COMMIT | MEM_RESERVE, VMT_ALLOC_PROTECTION)
                );
            if (!shadowVMTBuffer) {
                return HookStatus::MemoryAllocationFailed;
            }
            isAllocated = true;
        }
        else {
            uintptr_t gameModule = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
            if (!gameModule) {
                return HookStatus::InvalidModuleBase;
            }

            uintptr_t dataCaveRaw = FindGameDataCave(gameModule, totalVmtBytes);
            if (!dataCaveRaw) {
                return HookStatus::DataCaveNotFound;
            }

            shadowVMTBuffer = reinterpret_cast<void**>(dataCaveRaw);
            isAllocated = false;
        }

        shadowVMTBuffer[0] = originalVmt[-2];
        shadowVMTBuffer[1] = originalVmt[-1];

        void** customVmt = &shadowVMTBuffer[2];
        std::memcpy(customVmt, originalVmt, totalCount * sizeof(void*));
        customVmt[index] = detour;

        if (outOriginal) {
            *outOriginal = originalFunc;
        }

        HookEntry entry;
        entry.detour = detour;
        entry.classInstance = pInstance;
        entry.originalVmt = originalVmt;
        entry.customVmt = customVmt;
        entry.originalFunc = originalFunc;
        entry.index = index;
        entry.totalCount = totalCount;
        entry.isEnabled = false;
        entry.isAllocated = isAllocated;

        g_Hooks.push_back(entry);
        return HookStatus::OK;
    }

    /**
     * @brief 启用钩子
     * @param detour 自定义钩子函数的地址
     * @return 成功返回 true，失败返回 false
     */
    inline bool EnableHook(void* detour, uint32_t flags = 0) {
        if (flags & All_Hooks) {
            if (g_Hooks.empty()) {
                return false;
            }
            bool anySuccess = false;
            for (auto& entry : g_Hooks) {
                if (!entry.isEnabled) {
                    *(entry.classInstance) = entry.customVmt;
                    entry.isEnabled = true;
                    anySuccess = true;
                }
            }
            return anySuccess;
        }

        HookEntry* entry = FindHookEntry(detour);
        if (!entry || entry->isEnabled) {
            return false;
        }

        *(entry->classInstance) = entry->customVmt;
        entry->isEnabled = true;
        return true;
    }

    /**
     * @brief 启用钩子（按标志批量操作）
     * @param flags 钩子标志（如 All_Hooks）
     * @return 成功返回 true，失败返回 false
     */
    inline bool EnableHook(uint32_t flags) {
        return EnableHook(nullptr, flags);
    }

    /**
     * @brief 禁用钩子
     * @param detour 自定义钩子函数的地址
     * @return 成功返回 true，失败返回 false
     */
    inline bool DisableHook(void* detour, uint32_t flags = 0) {
        if (flags & All_Hooks) {
            if (g_Hooks.empty()) {
                return false;
            }
            bool anySuccess = false;
            for (auto& entry : g_Hooks) {
                if (entry.isEnabled) {
                    *(entry.classInstance) = entry.originalVmt;
                    entry.isEnabled = false;
                    anySuccess = true;
                }
            }
            return anySuccess;
        }

        HookEntry* entry = FindHookEntry(detour);
        if (!entry || !entry->isEnabled) {
            return false;
        }

        *(entry->classInstance) = entry->originalVmt;
        entry->isEnabled = false;
        return true;
    }

    /**
     * @brief 禁用钩子（按标志批量操作）
     * @param flags 钩子标志（如 All_Hooks）
     * @return 成功返回 true，失败返回 false
     */
    inline bool DisableHook(uint32_t flags) {
        return DisableHook(nullptr, flags);
    }

    /**
     * @brief 还原 Data Cave 内存，仅归零未被主模块修改过的字节
     * @param shadowBuffer 影子虚表缓冲区首地址（包含前缀元数据指针）
     * @param entry 钩子条目信息
     */
    inline void RevertDataCave(void** shadowBuffer, const HookEntry& entry) {
        auto currentBytes = reinterpret_cast<uint8_t*>(shadowBuffer);
        for (size_t i = 0; i < entry.totalCount + VMT_META_COUNT; ++i) {
            void* expectedValue = nullptr;
            if (i < VMT_META_COUNT) {
                expectedValue = entry.originalVmt[static_cast<ptrdiff_t>(i) - static_cast<ptrdiff_t>(VMT_META_COUNT)];
            }
            else {
                size_t funcIndex = i - VMT_META_COUNT;
                expectedValue = (funcIndex == entry.index) ? entry.detour : entry.originalVmt[funcIndex];
            }

            const auto expectedBytes = reinterpret_cast<const uint8_t*>(&expectedValue);
            for (size_t b = 0; b < sizeof(void*); ++b) {
                if (currentBytes[b] == expectedBytes[b]) {
                    currentBytes[b] = DATA_CAVE_RESET_BYTE;
                }
            }
            currentBytes += sizeof(void*);
        }
    }

    /**
     * @brief 移除并销毁钩子
     * @param detour 自定义钩子函数的地址
     * @return 成功返回 true，失败返回 false
     */
    inline bool RemoveHook(void* detour, uint32_t flags = 0) {
        if (flags & All_Hooks) {
            if (g_Hooks.empty()) {
                return false;
            }
            for (auto& entry : g_Hooks) {
                if (entry.isEnabled) {
                    *(entry.classInstance) = entry.originalVmt;
                }

                void** shadowBuffer = &(entry.customVmt[-2]);
                if (entry.isAllocated) {
                    VirtualFree(shadowBuffer, 0, MEM_RELEASE);
                }
                else {
                    RevertDataCave(shadowBuffer, entry);
                }
            }
            g_Hooks.clear();
            return true;
        }

        for (auto it = g_Hooks.begin(); it != g_Hooks.end(); ++it) {
            if (it->detour == detour) {
                if (it->isEnabled) {
                    *(it->classInstance) = it->originalVmt;
                }

                void** shadowBuffer = &(it->customVmt[-2]);
                if (it->isAllocated) {
                    VirtualFree(shadowBuffer, 0, MEM_RELEASE);
                }
                else {
                    RevertDataCave(shadowBuffer, *it);
                }

                g_Hooks.erase(it);
                return true;
            }
        }
        return false;
    }

    /**
     * @brief 移除并销毁钩子（按标志批量操作）
     * @param flags 钩子标志（如 All_Hooks）
     * @return 成功返回 true，失败返回 false
     */
    inline bool RemoveHook(uint32_t flags) {
        return RemoveHook(nullptr, flags);
    }

    /**
     * @brief 辅助函数：获取原始函数地址
     * @param detour 自定义钩子函数的地址
     * @return 原始函数地址，找不到则返回 nullptr
     */
    inline void* GetOriginal(void* detour) {
        HookEntry* entry = FindHookEntry(detour);
        return entry ? entry->originalFunc : nullptr;
    }

} // namespace ezVMT