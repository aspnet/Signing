using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace PackageSigning
{
    public class FileSigner
    {
        public string Subject { get; private set; }
        public string Spki { get; private set; }
        public IEnumerable<X509Certificate2> Certificates { get; private set; }
        public IEnumerable<FileSigner> CounterSigners { get; private set; }

        private FileSigner(string subject, string spki, IEnumerable<X509Certificate2> certificates)
        {
            Subject = subject;
            Spki = spki;
            Certificates = certificates;
        }

        internal static FileSigner FromX509Data(KeyInfoX509Data x509data)
        {
            var certificates = x509data.Certificates.Cast<X509Certificate2>();
            var subjectCert = certificates.FirstOrDefault();
            var keyIdentifierExtension = subjectCert?.Extensions?.OfType<X509SubjectKeyIdentifierExtension>()?.FirstOrDefault();
            return new FileSigner(
                subjectCert?.Subject,
                keyIdentifierExtension?.SubjectKeyIdentifier,
                certificates);
        }
    }
}