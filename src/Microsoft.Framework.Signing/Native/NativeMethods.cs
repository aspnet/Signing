using System;
using System.Runtime.InteropServices;

namespace Microsoft.Framework.Signing.Native
{
    internal static class NativeMethods
    {
        internal const uint PKCS_ATTRIBUTE = 22;

        internal const uint PKCS_7_ASN_ENCODING = 0x10000;
        internal const uint X509_ASN_ENCODING = 0x1;

        internal const int ERROR_MORE_DATA = 234;

        internal const uint TIMESTAMP_VERIFY_CONTEXT_SIGNATURE = 0x20;

        internal const string OID_PKCS9_COUNTERSIGNATURE = "1.2.840.113549.1.9.6";


        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa380228(v=vs.85).aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern SafeCryptMsgHandle CryptMsgOpenToDecode(
            CMSG_ENCODING dwMsgEncodingType,
            CMSG_OPENTODECODE_FLAGS dwFlags,
            uint dwMsgType,
            IntPtr hCryptProv,
            IntPtr pRecipientInfo,
            IntPtr pStreamInfo);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa380219(v=vs.85).aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CryptMsgClose(IntPtr hCryptMsg);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa380231(v=vs.85).aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CryptMsgUpdate(
            SafeCryptMsgHandle hCryptMsg,
            byte[] pbData,
            uint cbData,
            bool fFinal);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa380227(v=vs.85).aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CryptMsgGetParam(
            SafeCryptMsgHandle hCryptMsg,
            CMSG_GETPARAM_TYPE dwParamType,
            uint dwIndex,
            byte[] pvData,
            ref uint pcbData);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa380216(v=vs.85).aspx
        [DllImport("Crypt32.dll")]
        public static extern void CryptMemFree(IntPtr unmanagedContext);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa380220(v=vs.85).aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CryptMsgControl(
            SafeCryptMsgHandle hCryptMsg,
            uint dwFlags,
            CMSG_CONTROL_TYPE dwCtrlType,
            IntPtr pvCtrlPara);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379922(v=vs.85).aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CryptEncodeObjectEx(
            uint dwCertEncodingType,
            IntPtr lpszStructType,
            IntPtr pvStructInfo,
            uint dwFlags,
            IntPtr pEncodePara,
            IntPtr pvEncoded,
            ref uint pcbEncoded);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/dd433803%28v=vs.85%29.aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CryptRetrieveTimeStamp(
            [MarshalAs(UnmanagedType.LPWStr)] string wszUrl,
            uint dwRetrievalFlags,
            uint dwTimeout,
            [MarshalAs(UnmanagedType.LPStr)] string pszHashId,
            ref CRYPT_TIMESTAMP_PARA pPara,
            byte[] pbData,
            uint cbData,
            out IntPtr ppTsContext,
            IntPtr ppTsSigner,
            IntPtr phStore);

        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CryptVerifyTimeStampSignature(
            byte[] pbTSContentInfo,
            uint cbTSContentInfo,
            byte[] pbData,
            uint cbData,
            IntPtr hAdditionalStore,
            out IntPtr ppTsContext,
            IntPtr ppTsSigner,
            IntPtr phStore);

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376026(v=vs.85).aspx
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(
            IntPtr hCertStore,
            uint dwFlags);

        internal static int GetHRForWin32Error(int err)
        {
            if ((err & 0x80000000) == 0x80000000)
                return err;
            else
                return (err & 0x0000FFFF) | unchecked((int)0x80070000);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_TIMESTAMP_PARA
    {
        public string pszTSAPolicyId;
        public bool fRequestCerts;
        public CRYPT_INTEGER_BLOB Nonce;
        public uint cExtension;
        public IntPtr rgExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_TIMESTAMP_CONTEXT
    {
        public uint cbEncoded;
        public IntPtr pbEncoded;
        public IntPtr pTimeStamp;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_TIMESTAMP_INFO
    {
        public uint dwVersion;
        public string pszTSAPolicyId;
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        public CRYPT_INTEGER_BLOB_INTPTR HashedMessage;
        public CRYPT_INTEGER_BLOB_INTPTR SerialNumber;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftTime;
        public IntPtr pvAccuracy;
        public bool fOrdering;
        public CRYPT_INTEGER_BLOB_INTPTR Nonce;
        public CRYPT_INTEGER_BLOB_INTPTR Tsa;
        public uint cExtension;
        public IntPtr rgExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public string pszObjId;
        public CRYPT_INTEGER_BLOB_INTPTR Parameters;
    }

    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa381139(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ATTRIBUTE
    {
        [MarshalAs(UnmanagedType.LPStr)]
        public string pszObjId;

        public uint cValue;
        public IntPtr rgValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA
    {
        public uint cbSize;
        public uint dwSignerIndex;
        public CRYPT_INTEGER_BLOB_INTPTR BLOB;
    }

    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa381414(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_INTEGER_BLOB
    {
        public uint cbData;
        public byte[] pbData;

        public static CRYPT_INTEGER_BLOB FromByteArray(byte[] data)
        {
            return new CRYPT_INTEGER_BLOB()
            {
                cbData = (uint)data.Length,
                pbData = data
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_INTEGER_BLOB_INTPTR
    {
        public uint cbData;
        public IntPtr pbData;
    }

    internal enum CMSG_CONTROL_TYPE : uint
    {
        CMSG_CTRL_VERIFY_SIGNATURE = 1,
        CMSG_CTRL_DECRYPT = 2,
        CMSG_CTRL_VERIFY_HASH = 5,
        CMSG_CTRL_ADD_SIGNER = 6,
        CMSG_CTRL_DEL_SIGNER = 7,
        CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR = 8,
        CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR = 9,
        CMSG_CTRL_ADD_CERT = 10,
        CMSG_CTRL_DEL_CERT = 11,
        CMSG_CTRL_ADD_CRL = 12,
        CMSG_CTRL_DEL_CRL = 13,
        CMSG_CTRL_ADD_ATTR_CERT = 14,
        CMSG_CTRL_DEL_ATTR_CERT = 15,
        CMSG_CTRL_KEY_TRANS_DECRYPT = 16,
        CMSG_CTRL_KEY_AGREE_DECRYPT = 17,
        CMSG_CTRL_MAIL_LIST_DECRYPT = 18,
        CMSG_CTRL_VERIFY_SIGNATURE_EX = 19,
        CMSG_CTRL_ADD_CMS_SIGNER_INFO = 20,
        CMSG_CTRL_ENABLE_STRONG_SIGNATURE = 21
    }

    internal enum CMSG_GETPARAM_TYPE : uint
    {
        // Source: wincrypt.h
        CMSG_TYPE_PARAM = 1,
        CMSG_CONTENT_PARAM = 2,
        CMSG_BARE_CONTENT_PARAM = 3,
        CMSG_INNER_CONTENT_TYPE_PARAM = 4,
        CMSG_SIGNER_COUNT_PARAM = 5,
        CMSG_SIGNER_INFO_PARAM = 6,
        CMSG_SIGNER_CERT_INFO_PARAM = 7,
        CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8,
        CMSG_SIGNER_AUTH_ATTR_PARAM = 9,
        CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10,
        CMSG_CERT_COUNT_PARAM = 11,
        CMSG_CERT_PARAM = 12,
        CMSG_CRL_COUNT_PARAM = 13,
        CMSG_CRL_PARAM = 14,
        CMSG_ENVELOPE_ALGORITHM_PARAM = 15,
        CMSG_RECIPIENT_COUNT_PARAM = 17,
        CMSG_RECIPIENT_INDEX_PARAM = 18,
        CMSG_RECIPIENT_INFO_PARAM = 19,
        CMSG_HASH_ALGORITHM_PARAM = 20,
        CMSG_HASH_DATA_PARAM = 21,
        CMSG_COMPUTED_HASH_PARAM = 22,
        CMSG_ENCRYPT_PARAM = 26,
        CMSG_ENCRYPTED_DIGEST = 27,
        CMSG_ENCODED_SIGNER = 28,
        CMSG_ENCODED_MESSAGE = 29,
        CMSG_VERSION_PARAM = 30,
        CMSG_ATTR_CERT_COUNT_PARAM = 31,
        CMSG_ATTR_CERT_PARAM = 32,
        CMSG_CMS_RECIPIENT_COUNT_PARAM = 33,
        CMSG_CMS_RECIPIENT_INDEX_PARAM = 34,
        CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35,
        CMSG_CMS_RECIPIENT_INFO_PARAM = 36,
        CMSG_UNPROTECTED_ATTR_PARAM = 37,
        CMSG_SIGNER_CERT_ID_PARAM = 38,
        CMSG_CMS_SIGNER_INFO_PARAM = 39,
    }

    [Flags]
    internal enum CMSG_OPENTODECODE_FLAGS : uint
    {
        // Source: wincrypt.h
        None = 0,

        CMSG_DETACHED_FLAG = 0x00000004,
        CMSG_CRYPT_RELEASE_CONTEXT_FLAG = 0x00008000
    }

    [Flags]
    internal enum CMSG_ENCODING : uint
    {
        // Source: wincrypt.h
        X509_ASN_ENCODING = 0x00000001,
        PKCS_7_NDR_ENCODING = 0x00010000,

        Any = X509_ASN_ENCODING | PKCS_7_NDR_ENCODING
    }

    public class SafeCryptMsgHandle : SafeHandle
    {
        public SafeCryptMsgHandle() : base(IntPtr.Zero, ownsHandle: true) { }
        public SafeCryptMsgHandle(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle) { }

        public override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero;
            }
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CryptMsgClose(handle);
        }
    }
}