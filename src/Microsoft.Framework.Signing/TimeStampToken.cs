using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Framework.Signing.Native;

namespace Microsoft.Framework.Signing
{
    public class TimeStampToken
    {
        private TimeStampToken(int version, string tsaPolicyId, string hashAlgorithm, byte[] hashedMessage, DateTime timestampUtc, bool ordered, Signatory signer, bool isTrusted)
        {
            Version = version;
            TsaPolicyId = tsaPolicyId;
            HashAlgorithm = hashAlgorithm;
            HashedMessage = hashedMessage;
            TimestampUtc = timestampUtc;
            Ordered = ordered;
            Signatory = signer;
            IsTrusted = isTrusted;
        }

        public int Version { get; }
        public bool IsTrusted { get; }
        public string TsaPolicyId { get; }
        public string HashAlgorithm { get; }
        public byte[] HashedMessage { get; }
        public DateTime TimestampUtc { get; }
        public bool Ordered { get; }
        public Signatory Signatory { get; }

        internal static TimeStampToken FromTimestampInfo(CRYPT_TIMESTAMP_INFO info, Signatory signer, bool trusted)
        {
            string hashAlgorithm;
            try
            {
                var oid = Oid.FromOidValue(info.HashAlgorithm.pszObjId, OidGroup.HashAlgorithm);
                hashAlgorithm = oid.FriendlyName;
            }
            catch
            {
                hashAlgorithm = info.HashAlgorithm.pszObjId;
            }

            var hashedMessage = new byte[info.HashedMessage.cbData];
            Marshal.Copy(info.HashedMessage.pbData, hashedMessage, 0, hashedMessage.Length);

            return new TimeStampToken(
                (int)info.dwVersion,
                info.pszTSAPolicyId,
                hashAlgorithm,
                hashedMessage,
                DateTime.FromFileTime((long)(((ulong)(uint)info.ftTime.dwHighDateTime << 32) | (uint)info.ftTime.dwLowDateTime)).ToUniversalTime(),
                info.fOrdering,
                signer,
                trusted);
        }
    }
}