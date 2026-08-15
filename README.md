# ezVMT
A Simple C++ VMT Hook Library

## Example
```cpp
typedef void(__fastcall* tPostRender)(SDK::UGameViewportClient* _this, SDK::UCanvas* Canvas);
tPostRender oPostRender = nullptr;

void __fastcall hkPostRender(SDK::UGameViewportClient* _this, SDK::UCanvas* Canvas) {

    return oPostRender(_this, Canvas);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        SDK::UEngine* pEngine = SDK::UEngine::GetEngine();

        if (pEngine && pEngine->GameViewport) {
            SDK::UGameViewportClient* GameViewport = pEngine->GameViewport;

            // 1. 创建钩子
            ezVMT::CreateHook((void*)&hkPostRender, GameViewport, g_PostRender_Index, (void**)&oPostRender);

            // 2. 启用钩子
            ezVMT::EnableHook((void*)&hkPostRender);

            // 3. 禁用钩子
            // ezVMT::DisableHook((void*)&hkPostRender);

            // 4. 删除钩子
            // ezVMT::RemoveHook((void*)&hkPostRender);
        }

    }
    return TRUE;
}
```