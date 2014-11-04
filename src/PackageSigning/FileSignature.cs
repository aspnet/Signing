using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace PackageSigning
{
    public class FileSignature
    {
        private SignedXml _signedXml;

        public FileSigner Signer { get; private set; }

        private FileSignature(SignedXml signedXml)
        {
            _signedXml = signedXml;

            // Load the signer
            var x509data = signedXml.KeyInfo.OfType<KeyInfoX509Data>().FirstOrDefault();
            Signer = FileSigner.FromX509Data(x509data);
        }

        public static FileSignature Sign(MemoryStream file, X509Certificate2 cert)
        {
            var signedXml = new SignedXml();

            // Create a reference to the signature file to sign
            signedXml.AddReference(new Reference(file) {
                DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
            });

            // Create a signer info for the signature
            signedXml.SigningKey = cert.PrivateKey;
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));

            // Sign the content
            signedXml.ComputeSignature();

            // Load the signature in to the object
            return new FileSignature(signedXml);
        }
    }
}