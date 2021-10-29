#pragma once

#include <ntddk.h>
#include <wdm.h>
#include "ci.h"


HANDLE OpenFileReadHandleGuard(PCUNICODE_STRING imageFileName);

HANDLE CreateSectionHandleGuard(HANDLE fileHandle);

PVOID OpenSectionObjectGuard(HANDLE sectionHandle);

VOID CloseSectionObjectGuard(PVOID _object);

PVOID MmMapSectionViewGuard(PVOID sectionObject, SIZE_T* _viewSizeGet);

VOID MmUnmapSectionViewGuard(PVOID _baseAddrOfView);

VOID FreePolicyInfoGuard(PolicyInfo _policyInfo);