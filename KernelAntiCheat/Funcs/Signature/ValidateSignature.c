#include "ValidateSignature.h"
#include "..\..\Natives\Windows\ci.h"
#include "..\..\Natives\stdint.h"
#define SHA1_IDENTIFIER 0x8004
#define SHA256_IDENTIFIER 0x800C
#define IMAGE_DIRECTORY_ENTRY_SECURITY  4


PVOID RtlImageDirectoryEntryToData(PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size);
BOOL inRange(const BYTE* rangeStartAddr, const BYTE* rangeEndAddr, const BYTE* addrToCheck);
VOID parsePolicyInfo(const pPolicyInfo policyInfo);
BOOL ciCheckSignedFileWrapper(const LPWIN_CERTIFICATE win_cert, ULONG sizeOfSecurityDirectory);

void validateFileUsingCiValidateFileObject(PFILE_OBJECT fileObject)
{
    KdPrint(("Validating file using CiValidateFileObject...\n"));
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    PolicyInfo signerPolicyInfo;
    PolicyInfo timestampingAuthorityPolicyInfo;
    LARGE_INTEGER signingTime = { 0 };
    int digestSize = 64;
    int digestIdentifier = 0;
    BYTE digestBuffer[64] = { 0 };

    const NTSTATUS status = CiValidateFileObject(
        fileObject,
        0,
        0,
        &signerPolicyInfo,
        &timestampingAuthorityPolicyInfo,
        &signingTime,
        digestBuffer,
        &digestSize,
        &digestIdentifier
    );

    KdPrint(("CiValidateFileObject returned 0x%08X\n", status));
    if (NT_SUCCESS(status))
    {
        parsePolicyInfo(&signerPolicyInfo);
        return;
    }
}

void parsePolicyInfo(const pPolicyInfo policyInfo)
{
    if (policyInfo == NULL)
    {
        KdPrint(("parsePolicyInfo - paramter is null\n"));
        return;
    }

    if (policyInfo->structSize == 0)
    {
        KdPrint(("policy info is empty\n"));
        return;
    }

    if (policyInfo->certChainInfo == NULL)
    {
        KdPrint(("certChainInfo is null\n"));
        return;
    }

    const pCertChainInfoHeader chainInfoHeader = policyInfo->certChainInfo;

    const BYTE* startOfCertChainInfo = (BYTE*)(chainInfoHeader);
    const BYTE* endOfCertChainInfo = (BYTE*)(policyInfo->certChainInfo) + chainInfoHeader->bufferSize;

    if (!inRange(startOfCertChainInfo, endOfCertChainInfo, (BYTE*)chainInfoHeader->ptrToCertChainMembers))
    {
        KdPrint(("chain members out of range\n"));
        return;
    }

    // need to make sure we have enough room to accomodate the chain member struct
    if (!inRange(startOfCertChainInfo, endOfCertChainInfo, (BYTE*)chainInfoHeader->ptrToCertChainMembers + sizeof(CertChainMember)))
    {
        KdPrint(("chain member out of range\n"));
        return;
    }

    // we are interested in the first certificate in the chain - the signer itself
    pCertChainMember signerChainMember = chainInfoHeader->ptrToCertChainMembers;

    KdPrint(("Signer certificate:\n  digest algorithm - 0x%x\n  size - %zu\n  subject - %.*s\n  issuer - %.*s\n", \
        signerChainMember->digestIdetifier, \
        signerChainMember->certificate.size, \
        signerChainMember->subjectName.nameLen, \
        (char*)(signerChainMember->subjectName.pointerToName), \
        signerChainMember->issuerName.nameLen, \
        (char*)(signerChainMember->issuerName.pointerToName))                                            \
    );

    UNREFERENCED_PARAMETER(signerChainMember);
}

BOOL inRange(const BYTE* rangeStartAddr, const BYTE* rangeEndAddr, const BYTE* addrToCheck)
{
    if (addrToCheck > rangeEndAddr || addrToCheck < rangeStartAddr)
    {
        return FALSE;
    }

    return TRUE;
}
