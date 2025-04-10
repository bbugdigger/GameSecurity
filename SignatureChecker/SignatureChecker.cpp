#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <softpub.h>
#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "msi.lib")

void PrintLastError(const std::string& message) {
    DWORD error = GetLastError();
    std::cerr << message << " Error code: " << error << std::endl;
}

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
bool VerifyPESignature(const wchar_t* filePath) {
    DWORD dwLastError;

    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(nullptr, &policyGuid, &winTrustData);

    // Any hWVTStateData must be released by a call with close.
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    auto lStatus = WinVerifyTrust(nullptr, &policyGuid, &winTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        wprintf_s(L"The file \"%s\" is signed and the signature "
            L"was verified.\n",
            filePath);
        return true;
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            wprintf_s(L"The file \"%s\" is not signed.\n",
                filePath);
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            wprintf_s(L"An unknown error occurred trying to "
                L"verify the signature of the \"%s\" file.\n",
                filePath);
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        wprintf_s(L"The signature is present, but specifically "
            L"disallowed.\n");
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        wprintf_s(L"The signature is present, but not "
            L"trusted.\n");
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
            L"representing the subject or the publisher wasn't "
            L"explicitly trusted by the admin and admin policy "
            L"has disabled user trust. No signature, publisher "
            L"or timestamp errors.\n");
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        wprintf_s(L"Error is: 0x%x.\n",
            lStatus);
        break;
    }

    return status == ERROR_SUCCESS;
}

bool ExtractEmbeddedSignatureInfo(const wchar_t* filePath);

bool ExtractSignatureInfo(const wchar_t* filePath) {
    if (ExtractEmbeddedSignatureInfo(filePath)) {
        return true;
    }

    return false;
}

int wmain(int argc, wchar_t* argv[]) {
    //if (argc != 2) {
        //std::wcerr << L"Usage: " << argv[0] << L" <PE_File_Path>\n";
        //return 1;
    //}

    //const wchar_t* filePath = argv[1];
    //const wchar_t* filePath = L"C:\\Users\\dognu\\AppData\\Local\\Discord\\app - 1.0.9188\\Discord.exe";
    const wchar_t* filePath = L"C:\\Users\\dognu\\GameVandal\\IDA\\idapro90rc1\\portable\\windows\\ida.exe";
    //const wchar_t* filePath = L"C:\\Users\\dognu\\SystemInvestigation\\PE-bear\\PE-bear.exe";
    //const wchar_t* filePath = L"C:\\Users\\dognu\\SystemInvestigation\\SysinternalsSuite\\Winobj.exe";
    //const wchar_t* filePath = L"C:\\Program Files\\Cheat Engine\\Cheat Engine.exe";
    //const wchar_t* filePath = L"C:\\Windows\\System32\\notepad.exe";

    std::wcout << L"Verifying digital signature for: " << filePath << L"\n";

    if (VerifyPESignature(filePath)) {
        std::wcout << L"The file is digitally signed and the signature is valid.\n";
        ExtractSignatureInfo(filePath);
    }
    else {
        std::wcout << L"The file is not digitally signed or the signature is invalid.\n";
    }

    return 0;
}

bool ExtractEmbeddedSignatureInfo(const wchar_t* filePath) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;

    //https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptqueryobject
    BOOL result = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        nullptr,
        nullptr,
        nullptr,
        &hStore,
        &hMsg,
        nullptr
    );

    if (!result) {
        std::wcerr << L"CryptQueryObject failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) {
        std::wcerr << L"CryptMsgGetParam (size query) failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::vector<BYTE> signerInfoBuf(signerInfoSize);
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuf.data(), &signerInfoSize)) {
        std::wcerr << L"CryptMsgGetParam (data fetch) failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)signerInfoBuf.data();

    CERT_INFO certInfo{};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &certInfo,
        nullptr
    );

    if (!pCertContext) {
        std::wcerr << L"CertFindCertificateInStore failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"Found signer certificate.\n";

    // Print SHA256 thumbprint
    BYTE hash[32];
    DWORD hashSize = sizeof(hash);
    if (!CryptHashCertificate(
        NULL,
        CALG_SHA_256,
        0,
        pCertContext->pbCertEncoded,
        pCertContext->cbCertEncoded,
        hash,
        &hashSize
    )) {
        std::wcerr << L"Failed to hash the signer certificate. Error: " << GetLastError() << std::endl;
        CertFreeCertificateContext(pCertContext);
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
        return false;
    }

    std::wcout << L"SHA256 Thumbprint of Signer Certificate:\n";
    for (DWORD i = 0; i < hashSize; ++i) {
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)hash[i];
    }
    std::wcout << std::endl;

    // Clean up
    CertFreeCertificateContext(pCertContext);
    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);
    return true;
}
