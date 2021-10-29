#pragma once
#include <intrin.h>
#include "utils.h"
#include "..\Natives\Imports.h"

BOOL ScanSysThreads(PSYSTEM_MODULE_INFORMATION pModuleList);
BOOL ScanBigPool();
BOOL ScanPIDDB();
BOOL ScanHV();
BOOL ScanPhysMemHandles();
BOOL ScanPerfectInjector();
BOOL ScanDispatchDrivers(PSYSTEM_MODULE_INFORMATION pModuleList);
BOOL ScanCodeIntegrity();
BOOL CheckSSDT(PSYSTEM_MODULE_INFORMATION modules);