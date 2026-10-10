#include <Windows.h>
#include "../include/ezVMT.hpp"
#include "external/CppSDK/SDK/Basic.hpp"
#include "external/CppSDK/SDK/Engine_classes.hpp"
#include "external/CppSDK/SDK/CoreUObject_classes.hpp"
#include "external/Shadow-Gui/src/Shadow.h"
#include <format>

float g_dt = 0.f;
int g_PostRender_Index = 122;
int g_ActorTick_Index = 360;

typedef void(__fastcall* tPostRender)(SDK::UGameViewportClient* _this, SDK::UCanvas* Canvas);
tPostRender oPostRender = nullptr;

void __fastcall hkPostRender(SDK::UGameViewportClient* _this, SDK::UCanvas* Canvas) {
    Shadow::NewFrame(Canvas);
    static float time = 0.f;
	static float disabled_time = 10.f;
	time += g_dt;

    if (time >= disabled_time) {
        ezVMT::RemoveHook(ezVMT::All_Hooks);
    }

    Shadow::GetBackgroundDrawList()->AddText({ 5.f, 5.f }, {1.f, 1.f, 1.f, 1.f}, std::format("距离钩子被禁用还有 {:.1f}s", disabled_time - time));
    Shadow::Render();

    return oPostRender(_this, Canvas);
}

typedef void(__fastcall* tActorTick)(SDK::AActor* _this, float DeltaTime);
tActorTick oActorTick = nullptr;

void __fastcall hkActorTick(SDK::AActor* _this, float DeltaTime) {
	g_dt = DeltaTime;
    return oActorTick(_this, DeltaTime);
}

void MainThread(HMODULE hModpule) {
    while (true) {
        SDK::UWorld* pWorld = SDK::UWorld::GetWorld();
        SDK::UEngine* pEngine = SDK::UEngine::GetEngine();

        if (pEngine && pEngine->GameViewport && pWorld && pWorld->PersistentLevel && pWorld->PersistentLevel->Actors[0]) {
            // 1. 创建钩子
            ezVMT::CreateHook((void*)&hkPostRender, pEngine->GameViewport, g_PostRender_Index, (void**)&oPostRender, ezVMT::NO_Module_Stomping);
            ezVMT::CreateHook((void*)&hkActorTick, pWorld->PersistentLevel->Actors[0], g_ActorTick_Index, (void**)&oActorTick);

            // 2. 启用钩子
            ezVMT::EnableHook(ezVMT::All_Hooks);
            // ezVMT::EnableHook((void*)&hkPostRender);
            // ezVMT::EnableHook((void*)&hkActorTick);

            // 3. 禁用钩子
            // ezVMT::DisableHook((void*)&hkPostRender);

            // 4. 删除钩子
            // ezVMT::RemoveHook((void*)&hkPostRender);
            break;
        }

        Sleep(100);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        if (HANDLE h = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr)) CloseHandle(h);
    }
    return TRUE;
}