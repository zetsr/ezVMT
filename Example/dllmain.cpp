#include <Windows.h>
#include "../include/ezVMT.hpp"
#include "external/CppSDK/SDK/Basic.hpp"
#include "external/CppSDK/SDK/Engine_classes.hpp"
#include "external/CppSDK/SDK/CoreUObject_classes.hpp"
#include "external/Shadow-Gui/include/Shadow.h"
#include <format>

float g_dt = 0.f;
int g_PostRender_Index = 122;
int g_ActorTick_Index = 470;

typedef void(__fastcall* tPostRender)(SDK::UGameViewportClient* _this, SDK::UCanvas* Canvas);
tPostRender oPostRender = nullptr;

void __fastcall hkPostRender(SDK::UGameViewportClient* _this, SDK::UCanvas* Canvas) {
    Shadow::NewFrame(Canvas);
    Shadow::GetBackgroundDrawList()->AddText({ 5.f, 5.f }, {1.f, 1.f, 1.f, 1.f}, std::format("Delta Time: {}", g_dt));
    Shadow::Render();

    return oPostRender(_this, Canvas);
}

typedef void(__fastcall* tActorTick)(SDK::AActor* _this, float DeltaTime);
tActorTick oActorTick = nullptr;

void __fastcall hkActorTick(SDK::AActor* _this, float DeltaTime) {
	g_dt = DeltaTime;
    return oActorTick(_this, DeltaTime);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        SDK::UEngine* pEngine = SDK::UEngine::GetEngine();
        SDK::UWorld* pWorld = SDK::UWorld::GetWorld();

        if (pEngine && pEngine->GameViewport && pWorld && pWorld->PersistentLevel && pWorld->PersistentLevel->Actors[0]) {
            SDK::UGameViewportClient* GameViewport = pEngine->GameViewport;
			SDK::AActor* Actor = pWorld->PersistentLevel->Actors[0];

            // 1. 创建钩子
            ezVMT::CreateHook((void*)&hkPostRender, GameViewport, g_PostRender_Index, (void**)&oPostRender);
            ezVMT::CreateHook((void*)&hkActorTick, Actor, g_ActorTick_Index, (void**)&oActorTick);

            // 2. 启用钩子
            ezVMT::EnableHook((void*)&hkPostRender);
            ezVMT::EnableHook((void*)&hkActorTick);

            // 3. 禁用钩子
            // ezVMT::DisableHook((void*)&hkPostRender);

            // 4. 删除钩子
            // ezVMT::RemoveHook((void*)&hkPostRender);
        }

    }
    return TRUE;
}