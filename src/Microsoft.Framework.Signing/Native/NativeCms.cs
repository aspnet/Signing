using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Framework.Asn1;

namespace Microsoft.Framework.Signing.Native
{
    internal class NativeCms : IDisposable
    {
        private static readonly Oid SignatureTimeStampTokenAttributeOid = new Oid("1.2.840.113549.1.9.16.2.14");

        private SafeCryptMsgHandle _handle;
        private bool _detached;

        public NativeCms(IntPtr handle)
        {
            _handle = new SafeCryptMsgHandle(handle, ownsHandle: false);
        }

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

        public void AddCertificates(IEnumerable<byte[]> encodedCertificates)
        {
            foreach (var cert in encodedCertificates)
            {
                // Construct the blob
                IntPtr unmanagedCert = IntPtr.Zero;
                IntPtr unmanagedBlob = IntPtr.Zero;
                try
                {
                    // Build blob holder
                    unmanagedCert = Marshal.AllocHGlobal(cert.Length);
                    Marshal.Copy(cert, 0, unmanagedCert, cert.Length);
                    var blob = new CRYPT_INTEGER_BLOB_INTPTR()
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
                    NativeUtils.SafeFree(unmanagedCert);
                    NativeUtils.SafeFree(unmanagedBlob);
                }
            }
        }

        public void AddTimestamp(byte[] timeStampCms)
        {
            IntPtr unmanagedTimestamp = IntPtr.Zero;
            IntPtr unmanagedBlob = IntPtr.Zero;
            IntPtr unmanagedAttr = IntPtr.Zero;
            IntPtr unmanagedEncoded = IntPtr.Zero;
            IntPtr unmanagedAddAttr = IntPtr.Zero;
            try
            {
                // Wrap the timestamp in a CRYPT_INTEGER_BLOB and copy that to unmanaged memory
                unmanagedTimestamp = Marshal.AllocHGlobal(timeStampCms.Length);
                Marshal.Copy(timeStampCms, 0, unmanagedTimestamp, timeStampCms.Length);
                var blob = new CRYPT_INTEGER_BLOB_INTPTR()
                {
                    cbData = (uint)timeStampCms.Length,
                    pbData = unmanagedTimestamp
                };
                unmanagedBlob = Marshal.AllocHGlobal(Marshal.SizeOf(blob));
                Marshal.StructureToPtr(blob, unmanagedBlob, fDeleteOld: false);

                // Wrap it in a CRYPT_ATTRIBUTE and copy that too!
                var attr = new CRYPT_ATTRIBUTE()
                {
                    pszObjId = SignatureTimeStampTokenAttributeOid.Value,
                    cValue = 1,
                    rgValue = unmanagedBlob
                };
                unmanagedAttr = Marshal.AllocHGlobal(Marshal.SizeOf(attr));
                Marshal.StructureToPtr(attr, unmanagedAttr, fDeleteOld: false);

                // Now encode the object using ye olde double-call-to-find-out-the-length mechanism :)
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
                    BLOB = new CRYPT_INTEGER_BLOB_INTPTR()
                    {
                        cbData = encodedLength,
                        pbData = unmanagedEncoded
                    }
                };
                addAttr.cbSize = (uint)Marshal.SizeOf(addAttr);
                unmanagedAddAttr = Marshal.AllocHGlobal(Marshal.SizeOf(addAttr));
                Marshal.StructureToPtr(addAttr, unmanagedAddAttr, fDeleteOld: false);

                // Now store the timestamp in the message... FINALLY
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
                NativeUtils.SafeFree(unmanagedTimestamp);
                NativeUtils.SafeFree(unmanagedBlob);
                NativeUtils.SafeFree(unmanagedAttr);
                NativeUtils.SafeFree(unmanagedEncoded);
                NativeUtils.SafeFree(unmanagedAddAttr);
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
            NativeUtils.ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                _handle,
                param,
                index,
                null,
                ref valueLength));

            // Now allocate some memory for it
            byte[] data = new byte[(int)valueLength];

            // Get the actual digest
            NativeUtils.ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                _handle,
                param,
                index,
                data,
                ref valueLength));

            return data;
        }
    }
}
