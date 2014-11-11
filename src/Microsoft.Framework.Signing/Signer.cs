using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace PackageSigning
{
    public class Signer
    {
        public string Subject { get; private set; }
        public string Spki { get; private set; }
        public X509Certificate2 SignerCertificate { get; private set; }
        public X509Certificate2Collection Certificates { get; private set; }
        public IEnumerable<Signer> CounterSigners { get; private set; }

        private Signer(string subject, string spki, X509Certificate2 signerCertificate, X509Certificate2Collection certificates)
        {
            Subject = subject;
            Spki = spki;
            Certificates = certificates;
            SignerCertificate = signerCertificate;
        }

        internal static Signer FromSignerInfo(SignerInfo signerInfo, X509Certificate2Collection certificates, HashAlgorithm publicKeyIdentifierHashAlgorithm)
        {
            return new Signer(
                signerInfo.Certificate.Subject,
                signerInfo.Certificate.ComputePublicKeyIdentifier(publicKeyIdentifierHashAlgorithm),
                signerInfo.Certificate,
                certificates);
        }
    }
}