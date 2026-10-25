"""Native Windows Authenticode and Catalog Digital Signature Verifier.

Provides high-speed, zero-execution cryptographic signature validation using
Windows CryptoAPI and WinTrust (wintrust.dll, crypt32.dll, kernel32.dll).
Allows legitimate signed system and commercial software (Microsoft, Google, etc.)
to be verified in sub-millisecond time without executing untrusted binaries.
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class SignatureStatus:
    """Result of Authenticode and Catalog signature verification."""
    is_signed: bool
    is_trusted: bool
    provider: str  # "Authenticode Embedded", "Windows System Catalog", "None", "Unsupported Platform"
    subject: Optional[str] = None
    details: str = ""
    error_code: int = 0


# Windows WinTrust & CryptoAPI structures and constants
if sys.platform == "win32":
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", wintypes.BYTE * 8),
        ]

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    WTD_UI_NONE = 2
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_CHOICE_CATALOG = 2
    WTD_STATEACTION_IGNORE = 0
    WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80

    CERT_QUERY_OBJECT_FILE = 1
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
    CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("wszCatalogFile", wintypes.WCHAR * 260),
        ]

    class WINTRUST_CATALOG_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("dwCatalogVersion", wintypes.DWORD),
            ("pcwszCatalogFilePath", wintypes.LPCWSTR),
            ("pcwszMemberTag", wintypes.LPCWSTR),
            ("pcwszMemberFilePath", wintypes.LPCWSTR),
            ("hMemberFile", wintypes.HANDLE),
            ("pbCalculatedHash", ctypes.c_void_p),
            ("cbCalculatedHash", wintypes.DWORD),
            ("pcCatalogContext", ctypes.c_void_p),
            ("hCatAdmin", wintypes.HANDLE),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pInfo", ctypes.c_void_p),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    class CERT_CONTEXT(ctypes.Structure):
        _fields_ = [
            ("dwCertEncodingType", wintypes.DWORD),
            ("pbCertEncoded", ctypes.c_void_p),
            ("cbCertEncoded", wintypes.DWORD),
            ("pCertInfo", ctypes.c_void_p),
            ("hCertStore", wintypes.HANDLE),
        ]


class WindowsSignatureVerifier:
    """Zero-execution Authenticode and Catalog digital signature verifier."""

    def __init__(self, enabled: bool = True):
        self.is_windows = (sys.platform == "win32")
        self.enabled = enabled and self.is_windows
        self._wintrust = None
        self._kernel32 = None
        self._crypt32 = None
        self._h_cat_admin = None

        if self.enabled:
            self._init_win32_apis()

    def _init_win32_apis(self) -> None:
        """Initializes function prototypes for wintrust, kernel32, and crypt32."""
        try:
            self._wintrust = ctypes.windll.wintrust
            self._kernel32 = ctypes.windll.kernel32
            self._crypt32 = ctypes.windll.crypt32

            # WinVerifyTrust
            self._wintrust.WinVerifyTrust.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            self._wintrust.WinVerifyTrust.restype = wintypes.LONG

            # Catalog admin functions
            self._wintrust.CryptCATAdminAcquireContext.argtypes = [
                ctypes.POINTER(wintypes.HANDLE),
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            self._wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL

            self._wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            self._wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL

            self._wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            self._wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE

            self._wintrust.CryptCATCatalogInfoFromContext.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(CATALOG_INFO),
                wintypes.DWORD,
            ]
            self._wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

            self._wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.DWORD,
            ]
            self._wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

            self._wintrust.CryptCATAdminReleaseContext.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
            ]
            self._wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL

            # Acquire persistent catalog admin context for fast lookups
            h_admin = wintypes.HANDLE()
            if self._wintrust.CryptCATAdminAcquireContext(ctypes.byref(h_admin), None, 0):
                self._h_cat_admin = h_admin

            # Cert querying functions
            self._crypt32.CryptQueryObject.argtypes = [
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.HANDLE),
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            self._crypt32.CryptQueryObject.restype = wintypes.BOOL

            self._crypt32.CertFindCertificateInStore.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            self._crypt32.CertFindCertificateInStore.restype = ctypes.POINTER(CERT_CONTEXT)

            self._crypt32.CertGetNameStringW.argtypes = [
                ctypes.POINTER(CERT_CONTEXT),
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.LPWSTR,
                wintypes.DWORD,
            ]
            self._crypt32.CertGetNameStringW.restype = wintypes.DWORD

            self._crypt32.CertFreeCertificateContext.argtypes = [ctypes.POINTER(CERT_CONTEXT)]
            self._crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

            self._crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            self._crypt32.CertCloseStore.restype = wintypes.BOOL

        except Exception as e:
            self.enabled = False

    def __del__(self):
        if self._h_cat_admin and self._wintrust:
            try:
                self._wintrust.CryptCATAdminReleaseContext(self._h_cat_admin, 0)
            except Exception:
                pass

    def extract_signer_subject(self, file_path: str) -> Optional[str]:
        """Extracts the simple display name of the primary signer certificate."""
        if not self.enabled or not self._crypt32:
            return None
        try:
            h_store = wintypes.HANDLE()
            h_msg = wintypes.HANDLE()
            p_cert_context = ctypes.c_void_p()

            res = self._crypt32.CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                str(file_path),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                None,
                None,
                None,
                ctypes.byref(h_store),
                ctypes.byref(h_msg),
                ctypes.byref(p_cert_context),
            )
            if not res or not h_store.value:
                return None

            try:
                # 0x00010001 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                p_ctx = self._crypt32.CertFindCertificateInStore(h_store, 0x00010001, 0, 0, None, None)
                if not p_ctx:
                    return None
                try:
                    buf = ctypes.create_unicode_buffer(256)
                    self._crypt32.CertGetNameStringW(
                        p_ctx,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        None,
                        buf,
                        256,
                    )
                    return buf.value or None
                finally:
                    self._crypt32.CertFreeCertificateContext(p_ctx)
            finally:
                self._crypt32.CertCloseStore(h_store, 0)
        except Exception:
            return None

    def verify_embedded(self, file_path: str) -> SignatureStatus:
        """Verifies embedded Authenticode signature in the PE binary."""
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.pInfo = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
        data.dwStateAction = WTD_STATEACTION_IGNORE
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL

        status = self._wintrust.WinVerifyTrust(
            None,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(data),
        )

        uint_status = status & 0xFFFFFFFF
        if status == 0:
            subject = self.extract_signer_subject(file_path)
            return SignatureStatus(
                is_signed=True,
                is_trusted=True,
                provider="Authenticode Embedded",
                subject=subject or "Trusted Authenticode Signer",
                details="Valid trusted digital signature verified by Windows Trust Provider.",
                error_code=0,
            )

        # Common WinVerifyTrust return codes:
        # 0x800B0100: TRUST_E_NOSIGNATURE (No signature found)
        # 0x800B0101: CERT_E_EXPIRED (Certificate expired)
        # 0x800B0109: CERT_E_UNTRUSTEDROOT (Untrusted root)
        # 0x80096010: TRUST_E_BAD_DIGEST (File has been modified/tampered)
        is_signed = uint_status not in (0x800B0100, 0x80092009)
        return SignatureStatus(
            is_signed=is_signed,
            is_trusted=False,
            provider="Authenticode Embedded",
            subject=None,
            details=f"Verification failed with code 0x{uint_status:08X}",
            error_code=uint_status,
        )

    def verify_catalog(self, file_path: str) -> SignatureStatus:
        """Verifies Windows System Catalog signature for OS binaries."""
        if not self._h_cat_admin or not self._kernel32:
            return SignatureStatus(
                is_signed=False,
                is_trusted=False,
                provider="Windows System Catalog",
                details="Catalog verification uninitialized",
            )

        h_file = self._kernel32.CreateFileW(
            file_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if h_file == -1 or h_file == 0:
            return SignatureStatus(
                is_signed=False,
                is_trusted=False,
                provider="Windows System Catalog",
                details="Could not open file handle",
            )

        try:
            cb_hash = wintypes.DWORD(0)
            if not self._wintrust.CryptCATAdminCalcHashFromFileHandle(
                h_file, ctypes.byref(cb_hash), None, 0
            ):
                return SignatureStatus(
                    is_signed=False,
                    is_trusted=False,
                    provider="Windows System Catalog",
                    details="Could not calculate catalog hash",
                )

            pb_hash = (ctypes.c_byte * cb_hash.value)()
            if not self._wintrust.CryptCATAdminCalcHashFromFileHandle(
                h_file, ctypes.byref(cb_hash), pb_hash, 0
            ):
                return SignatureStatus(
                    is_signed=False,
                    is_trusted=False,
                    provider="Windows System Catalog",
                    details="Could not populate catalog hash",
                )

            h_cat_info = self._wintrust.CryptCATAdminEnumCatalogFromHash(
                self._h_cat_admin, pb_hash, cb_hash.value, 0, None
            )
            if not h_cat_info:
                return SignatureStatus(
                    is_signed=False,
                    is_trusted=False,
                    provider="Windows System Catalog",
                    details="File hash not found in Windows system catalog",
                )

            try:
                cat_info = CATALOG_INFO()
                cat_info.cbStruct = ctypes.sizeof(CATALOG_INFO)
                if not self._wintrust.CryptCATCatalogInfoFromContext(
                    h_cat_info, ctypes.byref(cat_info), 0
                ):
                    return SignatureStatus(
                        is_signed=False,
                        is_trusted=False,
                        provider="Windows System Catalog",
                        details="Could not retrieve catalog info",
                    )

                tag = "".join(f"{b:02X}" for b in bytes(pb_hash))
                cat_data = WINTRUST_CATALOG_INFO()
                cat_data.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
                cat_data.dwCatalogVersion = 0
                cat_data.pcwszCatalogFilePath = cat_info.wszCatalogFile
                cat_data.pcwszMemberTag = tag
                cat_data.pcwszMemberFilePath = file_path
                cat_data.hMemberFile = h_file
                cat_data.pbCalculatedHash = ctypes.cast(pb_hash, ctypes.c_void_p)
                cat_data.cbCalculatedHash = cb_hash.value
                cat_data.pcCatalogContext = None
                cat_data.hCatAdmin = self._h_cat_admin

                data = WINTRUST_DATA()
                data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
                data.dwUIChoice = WTD_UI_NONE
                data.fdwRevocationChecks = WTD_REVOKE_NONE
                data.dwUnionChoice = WTD_CHOICE_CATALOG
                data.pInfo = ctypes.cast(ctypes.pointer(cat_data), ctypes.c_void_p)
                data.dwStateAction = WTD_STATEACTION_IGNORE
                data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL

                status = self._wintrust.WinVerifyTrust(
                    None,
                    ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                    ctypes.byref(data),
                )

                if status == 0:
                    cat_name = Path(cat_info.wszCatalogFile).name
                    return SignatureStatus(
                        is_signed=True,
                        is_trusted=True,
                        provider="Windows System Catalog",
                        subject=f"Microsoft Windows Component ({cat_name})",
                        details="Catalog member verified by Windows Trust Provider.",
                        error_code=0,
                    )
                else:
                    return SignatureStatus(
                        is_signed=True,
                        is_trusted=False,
                        provider="Windows System Catalog",
                        details=f"Catalog verification failed with 0x{status & 0xFFFFFFFF:08X}",
                        error_code=status & 0xFFFFFFFF,
                    )
            finally:
                self._wintrust.CryptCATAdminReleaseCatalogContext(
                    self._h_cat_admin, h_cat_info, 0
                )
        finally:
            self._kernel32.CloseHandle(h_file)

    def verify_file(self, file_path: str | Path) -> SignatureStatus:
        """High-level verification trying embedded Authenticode first, then Catalog."""
        if not self.enabled:
            return SignatureStatus(
                is_signed=False,
                is_trusted=False,
                provider="Disabled / Non-Windows",
                details="Signature verification not enabled or non-Windows platform.",
            )

        path_str = str(Path(file_path).resolve())
        try:
            # 1. Embedded signature check (Third-party software, tools, vendor apps)
            emb_res = self.verify_embedded(path_str)
            if emb_res.is_trusted:
                return emb_res

            # 2. If no embedded signature, try Windows System Catalog check (System32 OS apps/DLLs)
            if emb_res.error_code == 0x800B0100:  # TRUST_E_NOSIGNATURE
                cat_res = self.verify_catalog(path_str)
                if cat_res.is_trusted:
                    return cat_res

            return emb_res
        except Exception as e:
            return SignatureStatus(
                is_signed=False,
                is_trusted=False,
                provider="Error",
                details=f"Exception during signature check: {str(e)}",
            )
