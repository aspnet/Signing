using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Microsoft.Framework.Signing
{
    public class Signatory
    {
        public X509Certificate2 SignerCertificate { get; private set; }
        public DateTime? SigningTime { get; private set; }

        private Signatory(X509Certificate2 signerCertificate, DateTime? signingTime)
        {
            SignerCertificate = signerCertificate;
            SigningTime = signingTime;
        }

        internal static Signatory FromSignerInfo(SignerInfo signerInfo)
        {
            DateTime? signingTime = null;
            var attr = signerInfo
                .SignedAttributes
                .Cast<CryptographicAttributeObject>()
                .Where(a => a.Oid.Value.Equals("1.2.840.113549.1.9.5", StringComparison.OrdinalIgnoreCase))
                .Select(a => new Pkcs9SigningTime(a.Values.Cast<AsnEncodedData>().First().RawData))
                .FirstOrDefault();
            if (attr != null)
            {
                signingTime = attr.SigningTime.ToUniversalTime();
            }

            return new Signatory(
                signerInfo.Certificate,
                signingTime);
        }
    }
}