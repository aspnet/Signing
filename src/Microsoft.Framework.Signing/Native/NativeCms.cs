using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.Framework.Signing.Native
{
    internal class NativeCms : IDisposable
    {
        private SafeCryptMsgHandle _handle;
        private bool _detached;

        private NativeCms(SafeCryptMsgHandle handle, bool detached)
        {
            _handle = handle;
            _detached = detached;
        }

        public byte[] GetEncryptedDigest()
        {
            return GetByteArrayAttribute(CMSG_GETPARAM_TYPE.CMSG_ENCRYPTED_DIGEST, index: 0);
        }

        public byte[] GetEncodedSignerInfo()
        {
            return GetByteArrayAttribute(CMSG_GETPARAM_TYPE.CMSG_ENCODED_SIGNER, index: 0);
        }

        public IEnumerable<byte[]> GetCertificates()
        {
            uint len = sizeof(uint);
            IntPtr certCountUnmanaged = IntPtr.Zero;
            int certCount = 0;
            try
            {
                certCountUnmanaged = Marshal.AllocHGlobal(sizeof(uint));
                if (!NativeMethods.CryptMsgGetParam(
                    _handle,
                    CMSG_GETPARAM_TYPE.CMSG_CERT_COUNT_PARAM,
                    0,
                    certCountUnmanaged,
                    ref len))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
                certCount = Marshal.ReadInt32(certCountUnmanaged);
            }
            finally
            {
                SafeFree(certCountUnmanaged);
            }

            // Now retrieve the certs
            List<byte[]> certs = new List<byte[]>(certCount);
            for (uint i = 0; i < certCount; i++)
            {
                certs.Add(GetByteArrayAttribute(CMSG_GETPARAM_TYPE.CMSG_CERT_PARAM, index: i));
            }
            return certs;
        }

        public void AddCertificates(IEnumerable<byte[]> encodedCertificates)
        {
            foreach (var cert in encodedCertificates)
            {
                // Construct the blob
                IntPtr unmanagedCert = IntPtr.Zero;
                IntPtr unmanagedBlob = IntPtr.Zero;
                try
                {
                    // Copy the certificate to unmanaged memory
                    unmanagedCert = Marshal.AllocHGlobal(cert.Length);
                    Marshal.Copy(cert, 0, unmanagedCert, cert.Length);

                    // Build blob holder
                    var blob = new CRYPT_INTEGER_BLOB()
                    {
                        cbData = (uint)cert.Length,
                        pbData = unmanagedCert
                    };

                    // Copy it to unmanaged memory
                    unmanagedBlob = Marshal.AllocHGlobal(Marshal.SizeOf(blob));
                    Marshal.StructureToPtr(blob, unmanagedBlob, fDeleteOld: false);

                    // Invoke the request
                    if (!NativeMethods.CryptMsgControl(
                        _handle,
                        dwFlags: 0,
                        dwCtrlType: CMSG_CONTROL_TYPE.CMSG_CTRL_ADD_CERT,
                        pvCtrlPara: unmanagedBlob))
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                    }
                }
                finally
                {
                    SafeFree(unmanagedCert);
                    SafeFree(unmanagedBlob);
                }
            }
        }

        public void AddCountersignature(byte[] signerInfo)
        {
            IntPtr unmanagedCountersignature = IntPtr.Zero;
            IntPtr unmanagedBlob = IntPtr.Zero;
            IntPtr unmanagedAttr = IntPtr.Zero;
            IntPtr unmanagedEncoded = IntPtr.Zero;
            IntPtr unmanagedAddAttr = IntPtr.Zero;
            try
            {
                // Copy the signature to unmanaged memory
                unmanagedCountersignature = Marshal.AllocHGlobal(signerInfo.Length);
                Marshal.Copy(signerInfo, 0, unmanagedCountersignature, signerInfo.Length);

                // Wrap it in a CRYPT_INTEGER_BLOB and copy that to unmanaged memory
                var blob = new CRYPT_INTEGER_BLOB()
                {
                    cbData = (uint)signerInfo.Length,
                    pbData = unmanagedCountersignature
                };
                unmanagedBlob = Marshal.AllocHGlobal(Marshal.SizeOf(blob));
                Marshal.StructureToPtr(blob, unmanagedBlob, fDeleteOld: false);

                // Wrap it in a CRYPT_ATTRIBUTE and copy that too!
                var attr = new CRYPT_ATTRIBUTE()
                {
                    pszObjId = NativeMethods.OID_PKCS9_COUNTERSIGNATURE,
                    cValue = 1,
                    rgValue = unmanagedBlob
                };
                unmanagedAttr = Marshal.AllocHGlobal(Marshal.SizeOf(attr));
                Marshal.StructureToPtr(attr, unmanagedAttr, fDeleteOld: false);

                // Now encode the object using ye olde double-call find-out-the-length mechanism :)
                uint encodedLength = 0;
                if (!NativeMethods.CryptEncodeObjectEx(
                    dwCertEncodingType: NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    lpszStructType: new IntPtr(NativeMethods.PKCS_ATTRIBUTE),
                    pvStructInfo: unmanagedAttr,
                    dwFlags: 0,
                    pEncodePara: IntPtr.Zero,
                    pvEncoded: IntPtr.Zero,
                    pcbEncoded: ref encodedLength))
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err != NativeMethods.ERROR_MORE_DATA)
                    {
                        Marshal.ThrowExceptionForHR(NativeMethods.GetHRForWin32Error(err));
                    }
                }

                unmanagedEncoded = Marshal.AllocHGlobal((int)encodedLength);
                if (!NativeMethods.CryptEncodeObjectEx(
                    dwCertEncodingType: NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    lpszStructType: new IntPtr(NativeMethods.PKCS_ATTRIBUTE),
                    pvStructInfo: unmanagedAttr,
                    dwFlags: 0,
                    pEncodePara: IntPtr.Zero,
                    pvEncoded: unmanagedEncoded,
                    pcbEncoded: ref encodedLength))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }

                // Create the structure used to add the attribute
                var addAttr = new CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA()
                {
                    dwSignerIndex = 0,
                    BLOB = new CRYPT_INTEGER_BLOB()
                    {
                        cbData = encodedLength,
                        pbData = unmanagedEncoded
                    }
                };
                addAttr.cbSize = (uint)Marshal.SizeOf(addAttr);
                unmanagedAddAttr = Marshal.AllocHGlobal(Marshal.SizeOf(addAttr));
                Marshal.StructureToPtr(addAttr, unmanagedAddAttr, fDeleteOld: false);

                // Now store the countersignature in the message... FINALLY
                if (!NativeMethods.CryptMsgControl(
                    _handle,
                    dwFlags: 0,
                    dwCtrlType: CMSG_CONTROL_TYPE.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR,
                    pvCtrlPara: unmanagedAddAttr))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
            }
            finally
            {
                SafeFree(unmanagedCountersignature);
                SafeFree(unmanagedBlob);
                SafeFree(unmanagedAttr);
                SafeFree(unmanagedEncoded);
                SafeFree(unmanagedAddAttr);
            }
        }

        public byte[] Encode()
        {
            return GetByteArrayAttribute(CMSG_GETPARAM_TYPE.CMSG_ENCODED_MESSAGE, index: 0);
        }

        public static NativeCms Decode(byte[] input, bool detached)
        {
            var handle = NativeMethods.CryptMsgOpenToDecode(
                CMSG_ENCODING.Any,
                detached ? CMSG_OPENTODECODE_FLAGS.CMSG_DETACHED_FLAG : CMSG_OPENTODECODE_FLAGS.None,
                0u,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            // Load the data into the message
            if (!NativeMethods.CryptMsgUpdate(handle, input, (uint)input.Length, fFinal: true))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            return new NativeCms(handle, detached);
        }

        public void Dispose()
        {
            _handle.Dispose();
        }

        private byte[] GetByteArrayAttribute(CMSG_GETPARAM_TYPE param, uint index)
        {
            // Get the length of the attribute
            uint valueLength = 0;
            if (!NativeMethods.CryptMsgGetParam(
                _handle,
                param,
                index,
                IntPtr.Zero,
                ref valueLength))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            // Now allocate some memory for it
            IntPtr unmanagedDigestPointer = IntPtr.Zero;
            byte[] data;
            try
            {
                unmanagedDigestPointer = Marshal.AllocHGlobal((int)valueLength);

                // Get the actual digest
                if (!NativeMethods.CryptMsgGetParam(
                    _handle,
                    param,
                    index,
                    unmanagedDigestPointer,
                    ref valueLength))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }

                // Pull it in to managed memory and return it
                data = new byte[valueLength];
                Marshal.Copy(unmanagedDigestPointer, data, 0, data.Length);
            }
            finally
            {
                SafeFree(unmanagedDigestPointer);
            }
            return data;
        }

        private static void SafeFree(IntPtr unmanagedCountersignature)
        {
            if (unmanagedCountersignature != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(unmanagedCountersignature);
            }
        }
    }
}
