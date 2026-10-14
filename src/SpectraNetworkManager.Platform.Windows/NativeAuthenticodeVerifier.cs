using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;
using Windows.Win32.Security.Cryptography.Catalog;
using Windows.Win32.Security.WinTrust;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>
/// Verifies digital signatures natively using Win32 WinVerifyTrust and CryptCATAdmin* APIs.
/// Accurately verifies both embedded signatures and Windows security catalog signatures.
/// </summary>
[SupportedOSPlatform("windows5.1.2600")]
public static class NativeAuthenticodeVerifier
{
    private const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

    public static unsafe SignatureInfo VerifyFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new SignatureInfo(SignatureStatus.Unknown, null, false, "file not found");
        }

        // Try embedded signature first
        var embedded = VerifyEmbedded(path);
        if (embedded.Status is SignatureStatus.Valid or SignatureStatus.Tampered)
        {
            return embedded;
        }

        // If not embedded signed, check security catalog (e.g. for Windows OS binaries)
        var catalog = VerifyCatalog(path);
        if (catalog.Status != SignatureStatus.Unknown && catalog.Status != SignatureStatus.NotSigned)
        {
            return catalog;
        }

        return embedded.Status != SignatureStatus.Unknown ? embedded : catalog;
    }

    private static unsafe SignatureInfo VerifyEmbedded(string path)
    {
        fixed (char* pathPtr = path)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath = pathPtr,
                hFile = default,
                pgKnownSubject = null
            };

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                pPolicyCallbackData = null,
                pSIPClientData = null,
                dwUIChoice = WINTRUST_DATA_UICHOICE.WTD_UI_NONE,
                fdwRevocationChecks = WINTRUST_DATA_REVOCATION_CHECKS.WTD_REVOKE_NONE,
                dwUnionChoice = WINTRUST_DATA_UNION_CHOICE.WTD_CHOICE_FILE,
                dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_VERIFY,
                hWVTStateData = default,
                pwszURLReference = null,
                dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS.WTD_SAFER_FLAG | WINTRUST_DATA_PROVIDER_FLAGS.WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            data.Anonymous.pFile = &fileInfo;

            Guid action = PInvoke.WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int hr = PInvoke.WinVerifyTrust(HWND.Null, ref action, &data);

            SignatureInfo result;
            try
            {
                result = ParseTrustResult(hr, data.hWVTStateData);
            }
            finally
            {
                data.dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_CLOSE;
                PInvoke.WinVerifyTrust(HWND.Null, ref action, &data);
            }

            return result;
        }
    }

    private static unsafe SignatureInfo VerifyCatalog(string path)
    {
        nint hCatAdmin = 0;
        nint hCatInfo = 0;

        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var safeHandle = fs.SafeFileHandle;

            // Acquire CatAdmin context
            if (!PInvoke.CryptCATAdminAcquireContext(out hCatAdmin, null))
            {
                return new SignatureInfo(SignatureStatus.NotSigned, null, false);
            }

            // Calculate file hash
            uint hashSize = 0;
            PInvoke.CryptCATAdminCalcHashFromFileHandle(safeHandle, ref hashSize, Span<byte>.Empty);
            if (hashSize == 0)
            {
                return new SignatureInfo(SignatureStatus.NotSigned, null, false);
            }

            byte[] hash = new byte[hashSize];
            if (!PInvoke.CryptCATAdminCalcHashFromFileHandle(safeHandle, ref hashSize, hash.AsSpan()))
            {
                return new SignatureInfo(SignatureStatus.NotSigned, null, false);
            }

            hCatInfo = PInvoke.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash.AsSpan());
            if (hCatInfo == 0)
            {
                return new SignatureInfo(SignatureStatus.NotSigned, null, false);
            }

            // Found catalog context
            var catInfoStruct = new CATALOG_INFO { cbStruct = (uint)sizeof(CATALOG_INFO) };
            if (!PInvoke.CryptCATCatalogInfoFromContext(hCatInfo, ref catInfoStruct, 0))
            {
                return new SignatureInfo(SignatureStatus.NotSigned, null, false);
            }

            string catFilePath = catInfoStruct.wszCatalogFile.ToString();
            return VerifyCatalogMember(catFilePath, path, hash);
        }
        catch (Exception ex)
        {
            return new SignatureInfo(SignatureStatus.Unknown, null, false, ex.Message);
        }
        finally
        {
            if (hCatInfo != 0 && hCatAdmin != 0)
            {
                PInvoke.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
            if (hCatAdmin != 0)
            {
                PInvoke.CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }
    }

    private static unsafe SignatureInfo VerifyCatalogMember(string catalogPath, string memberPath, byte[] hash)
    {
        string hashTag = Convert.ToHexString(hash);

        fixed (char* catPathPtr = catalogPath)
        fixed (char* memPathPtr = memberPath)
        fixed (char* tagPtr = hashTag)
        fixed (byte* pbHash = hash)
        {
            var catInfo = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catPathPtr,
                pcwszMemberFilePath = memPathPtr,
                pcwszMemberTag = tagPtr,
                pbCalculatedFileHash = pbHash,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = default
            };

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                pPolicyCallbackData = null,
                pSIPClientData = null,
                dwUIChoice = WINTRUST_DATA_UICHOICE.WTD_UI_NONE,
                fdwRevocationChecks = WINTRUST_DATA_REVOCATION_CHECKS.WTD_REVOKE_NONE,
                dwUnionChoice = WINTRUST_DATA_UNION_CHOICE.WTD_CHOICE_CATALOG,
                dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_VERIFY,
                hWVTStateData = default,
                pwszURLReference = null,
                dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS.WTD_SAFER_FLAG | WINTRUST_DATA_PROVIDER_FLAGS.WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            data.Anonymous.pCatalog = &catInfo;

            Guid action = PInvoke.WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int hr = PInvoke.WinVerifyTrust(HWND.Null, ref action, &data);

            SignatureInfo result;
            try
            {
                result = ParseTrustResult(hr, data.hWVTStateData);
            }
            finally
            {
                data.dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_CLOSE;
                PInvoke.WinVerifyTrust(HWND.Null, ref action, &data);
            }

            return result;
        }
    }

    private static unsafe SignatureInfo ParseTrustResult(int hr, HANDLE hWVTStateData)
    {
        const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        const int TRUST_E_BAD_DIGEST = unchecked((int)0x800B0004);
        const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
        const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
        const int CERT_E_CHAINING = unchecked((int)0x800B010A);
        const int CERT_E_EXPIRED = unchecked((int)0x800B0101);

        if (hr == TRUST_E_NOSIGNATURE)
        {
            return new SignatureInfo(SignatureStatus.NotSigned, null, false);
        }

        if (hr == TRUST_E_BAD_DIGEST)
        {
            return new SignatureInfo(SignatureStatus.Tampered, null, false, "Signature digest mismatch");
        }

        string? publisher = TryExtractPublisher(hWVTStateData, out bool isOsBinary);

        if (hr == 0)
        {
            return new SignatureInfo(SignatureStatus.Valid, publisher, isOsBinary);
        }

        if (hr is CERT_E_UNTRUSTEDROOT or TRUST_E_EXPLICIT_DISTRUST or CERT_E_CHAINING or CERT_E_EXPIRED)
        {
            return new SignatureInfo(SignatureStatus.Untrusted, publisher, false, $"Untrusted (0x{hr:X8})");
        }

        return new SignatureInfo(SignatureStatus.Unknown, publisher, false, $"Trust error 0x{hr:X8}");
    }

    private static unsafe string? TryExtractPublisher(HANDLE hWVTStateData, out bool isOsBinary)
    {
        isOsBinary = false;
        if (hWVTStateData == default) return null;

        try
        {
            var provData = PInvoke.WTHelperProvDataFromStateData(hWVTStateData);
            if (provData == null) return null;

            var signer = PInvoke.WTHelperGetProvSignerFromChain(ref *(CRYPT_PROVIDER_DATA*)provData, 0, false, 0);
            if (signer == null) return null;

            var cert = PInvoke.WTHelperGetProvCertFromChain(signer, 0);
            if (cert == null || cert->pCert == null) return null;

            Span<char> buffer = stackalloc char[256];
            fixed (char* pBuf = buffer)
            {
                uint chars = PInvoke.CertGetNameString(
                    cert->pCert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    null,
                    new PWSTR(pBuf),
                    (uint)buffer.Length);

                if (chars > 1)
                {
                    string name = new string(buffer[..(int)(chars - 1)]);
                    if (name.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) &&
                        (name.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                         name.Contains("Operating System", StringComparison.OrdinalIgnoreCase)))
                    {
                        isOsBinary = true;
                    }
                    return name;
                }
            }
        }
        catch
        {
            // Ignore certificate parse errors
        }

        return null;
    }
}
