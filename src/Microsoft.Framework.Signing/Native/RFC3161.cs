﻿using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing.Native
{
    internal static class RFC3161
    {
        internal static SignedCms RequestTimestamp(byte[] data, string hashAlgorithmOid, Uri timestampingAuthorityUrl)
        {
            var para = new CRYPT_TIMESTAMP_PARA()
            {
                fRequestCerts = true
            };

            IntPtr unmanagedContext = IntPtr.Zero;
            byte[] encodedResponse;
            try
            {
                NativeUtils.ThrowIfFailed(NativeMethods.CryptRetrieveTimeStamp(
                    wszUrl: timestampingAuthorityUrl.ToString(),
                    dwRetrievalFlags: NativeMethods.TIMESTAMP_VERIFY_CONTEXT_SIGNATURE,
                    dwTimeout: 5 * 1000 /* 5 second timeout */,
                    pszHashId: hashAlgorithmOid,
                    pPara: ref para,
                    pbData: data,
                    cbData: (uint)data.Length,
                    ppTsContext: out unmanagedContext,
                    ppTsSigner: IntPtr.Zero,
                    phStore: IntPtr.Zero));

                // Copy the encoded response out
                var context = (CRYPT_TIMESTAMP_CONTEXT)Marshal.PtrToStructure(unmanagedContext, typeof(CRYPT_TIMESTAMP_CONTEXT));
                encodedResponse = new byte[context.cbEncoded];
                Marshal.Copy(context.pbEncoded, encodedResponse, 0, (int)context.cbEncoded);
            }
            finally
            {
                if (unmanagedContext != IntPtr.Zero)
                {
                    NativeMethods.CryptMemFree(unmanagedContext);
                }
            }

            SignedCms cms = new SignedCms();
            cms.Decode(encodedResponse);
            return cms;
        }

        internal static TimeStampToken VerifyTimestamp(byte[] data, SignedCms timestampCms)
        {
            var signer = Signatory.FromSignerInfo(timestampCms.SignerInfos[0]);

            bool trusted = signer.SignerCertificate.Verify();

            var contentInfo = timestampCms.Encode();

            IntPtr unmanagedContext = IntPtr.Zero;
            try
            {
                NativeUtils.ThrowIfFailed(NativeMethods.CryptVerifyTimeStampSignature(
                    pbTSContentInfo: contentInfo,
                    cbTSContentInfo: (uint)contentInfo.Length,
                    pbData: data,
                    cbData: (uint)data.Length,
                    hAdditionalStore: IntPtr.Zero,
                    ppTsContext: out unmanagedContext,
                    ppTsSigner: IntPtr.Zero,
                    phStore: IntPtr.Zero));

                // Copy the context out
                var context = (CRYPT_TIMESTAMP_CONTEXT)Marshal.PtrToStructure(unmanagedContext, typeof(CRYPT_TIMESTAMP_CONTEXT));

                // Copy the info out
                var info = (CRYPT_TIMESTAMP_INFO)Marshal.PtrToStructure(context.pTimeStamp, typeof(CRYPT_TIMESTAMP_INFO));

                return TimeStampToken.FromTimestampInfo(info, signer, trusted);
            }
            finally
            {
                if (unmanagedContext != IntPtr.Zero)
                {
                    NativeMethods.CryptMemFree(unmanagedContext);
                }
            }

        }
    }
}