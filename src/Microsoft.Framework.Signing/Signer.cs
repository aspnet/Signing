using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Microsoft.Framework.Signing
{
    public class Signer
    {
        public string Subject { get; private set; }
        public string Spki { get; private set; }
        public X509Certificate2 SignerCertificate { get; private set; }
        public X509Certificate2Collection Certificates { get; private set; }
        
        private Signer(string subject, string spki, X509Certificate2 signerCertificate, X509Certificate2Collection certificates)
        {
            Spki = spki;
            Certificates = certificates;
            SignerCertificate = signerCertificate;
        }

        internal static Signer FromSignerInfo(SignerInfo signerInfo, X509Certificate2Collection certificates)
        {
            return new Signer(
                signerInfo.Certificate.Subject,
                signerInfo.Certificate.ComputePublicKeyIdentifier(),
                signerInfo.Certificate,
                certificates);
        }
    }
}