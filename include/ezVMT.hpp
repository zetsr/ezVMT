#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <cstring>

namespace ezVMT {

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
    };

    // 全局钩子记录列表
    inline std::vector<HookEntry> g_Hooks;

    // 检查候选 Data Cave 是否与已存在的 Hook 内存重叠
    inline bool IsDataCaveOverlap(uintptr_t start, size_t size) {
        uintptr_t end = start + size;
        for (const auto& entry : g_Hooks) {
            if (entry.customVmt) {
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
     * @return 成功返回 true，失败返回 false
     */
    inline bool CreateHook(void* detour, void* classInstance, size_t index, void** outOriginal = nullptr) {
        if (!detour || !classInstance) {
            return false;
        }

        if (FindHookEntry(detour) != nullptr) {
            return false;
        }

        void*** pInstance = reinterpret_cast<void***>(classInstance);
        void** originalVmt = *pInstance;

        if (!originalVmt) {
            return false;
        }

        size_t totalCount = GetVMTSizeDynamic(originalVmt);
        if (index >= totalCount || totalCount == 0) {
            return false;
        }

        uintptr_t gameModule = (uintptr_t)GetModuleHandleA(NULL);
        size_t totalVmtBytes = (totalCount + 2) * sizeof(void*);

        uintptr_t dataCaveRaw = FindGameDataCave(gameModule, totalVmtBytes);
        if (!dataCaveRaw) {
            return false;
        }

        void** shadowVMTBuffer = reinterpret_cast<void**>(dataCaveRaw);

        shadowVMTBuffer[0] = originalVmt[-2];
        shadowVMTBuffer[1] = originalVmt[-1];

        void** customVmt = &shadowVMTBuffer[2];
        std::memcpy(customVmt, originalVmt, totalCount * sizeof(void*));
        customVmt[index] = detour;

        if (outOriginal) {
            *outOriginal = originalVmt[index];
        }

        HookEntry entry;
        entry.detour = detour;
        entry.classInstance = pInstance;
        entry.originalVmt = originalVmt;
        entry.customVmt = customVmt;
        entry.originalFunc = originalVmt[index];
        entry.index = index;
        entry.totalCount = totalCount;
        entry.isEnabled = false;

        g_Hooks.push_back(entry);
        return true;
    }

    /**
     * @brief 启用钩子
     * @param detour 自定义钩子函数的地址
     * @return 成功返回 true，失败返回 false
     */
    inline bool EnableHook(void* detour) {
        HookEntry* entry = FindHookEntry(detour);
        if (!entry || entry->isEnabled) {
            return false;
        }

        *(entry->classInstance) = entry->customVmt;
        entry->isEnabled = true;
        return true;
    }

    /**
     * @brief 禁用钩子
     * @param detour 自定义钩子函数的地址
     * @return 成功返回 true，失败返回 false
     */
    inline bool DisableHook(void* detour) {
        HookEntry* entry = FindHookEntry(detour);
        if (!entry || !entry->isEnabled) {
            return false;
        }

        *(entry->classInstance) = entry->originalVmt;
        entry->isEnabled = false;
        return true;
    }

    /**
     * @brief 移除并销毁钩子
     * @param detour 自定义钩子函数的地址
     * @return 成功返回 true，失败返回 false
     */
    inline bool RemoveHook(void* detour) {
        for (auto it = g_Hooks.begin(); it != g_Hooks.end(); ++it) {
            if (it->detour == detour) {
                if (it->isEnabled) {
                    *(it->classInstance) = it->originalVmt;
                }

                void** shadowBuffer = &(it->customVmt[-2]);
                std::memset(shadowBuffer, 0, (it->totalCount + 2) * sizeof(void*));

                g_Hooks.erase(it);
                return true;
            }
        }
        return false;
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