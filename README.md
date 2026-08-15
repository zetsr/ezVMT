# ezVMT
A Simple C++ VMT Hook Library

## Example
```cpp
void __fastcall hkPostRender(SDK::UGameViewportClient* _this, SDK::UCanvas* Canvas) {
    return oPostRender(_this, Canvas);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        SDK::UEngine* pEngine = SDK::UEngine::GetEngine();

        if (pEngine && pEngine->GameViewport) {
            SDK::UGameViewportClient* GameViewport = pEngine->GameViewport;
            ezVMT::CreateHook((void*)&hkPostRender, GameViewport, g_PostRender_Index, (void**)&oPostRender);
            ezVMT::EnableHook((void*)&hkPostRender);
        }

    }
    return TRUE;
}
```