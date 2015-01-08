using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal class SignOptions
    {
        private static Dictionary<string, Action<CommandOption, SignOptions>> _bindings = new Dictionary<string, Action<CommandOption, SignOptions>>(StringComparer.OrdinalIgnoreCase)
        {
            { "auto-select", (opt, self) => self.AutoSelect = opt.HasValue() },
            { "file", (opt, self) => self.CertificateFile = opt.Value() },
            { "add-certs", (opt, self) => self.AddCertificatesFile = opt.Value() },
            { "issuer", (opt, self) => self.IssuerName = opt.Value() },
            { "subject", (opt, self) => self.SubjectName = opt.Value() },
            { "password", (opt, self) => self.Password = opt.Value() },
            { "store", (opt, self) => self.StoreName = opt.Value() },
            { "machine-store", (opt, self) => self.MachineStore = opt.HasValue() },
            { "thumbprint", (opt, self) => self.Thumbprint = opt.Value() },
            { "key-provider", (opt, self) => self.CspName = opt.Value() },
            { "key-container", (opt, self) => self.KeyContainer = opt.Value() },
            { "output", (opt, self) => self.Output = opt.Value() },
            { "timestamper", (opt, self) => self.Timestamper = opt.Value() },
            { "timestamper-algorithm", (opt, self) => self.TimestamperAlgorithm = opt.Value() },
        };

        public bool AutoSelect { get; set; }
        public string CertificateFile { get; set; }
        public string AddCertificatesFile { get; set; }
        public string IssuerName { get; set; }
        public string SubjectName { get; set; }
        public string Password { get; set; }
        public string StoreName { get; set; }
        public bool MachineStore { get; set; }
        public string Thumbprint { get; set; }
        public string CspName { get; set; }
        public string KeyContainer { get; set; }
        public string Output { get; set; }
        public string FileName { get; set; }
        public string Timestamper { get; set; }
        public string TimestamperAlgorithm { get; set; }

        public X509Certificate2 FindCert(out X509Certificate2Collection includedCerts)
        {
            includedCerts = null;

            X509Store store = null;
            try
            {
                // Get the pool of certificates to search
                X509Certificate2Collection pool;
                if (!string.IsNullOrEmpty(CertificateFile))
                {
                    // If there is a file, load that
                    pool = new X509Certificate2Collection();
                    pool.Import(CertificateFile, Password, X509KeyStorageFlags.DefaultKeySet);
                    includedCerts = pool;
                }
                else
                {
                    // Otherwise, open the specified store
                    store = new X509Store(StoreName ?? "My", MachineStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly);

                    // Code Signing EKU = 1.3.6.1.5.5.7.3.3
                    pool = store.Certificates
                        .Find(X509FindType.FindByTimeValid, DateTime.Now, validOnly: false)
                        .Find(X509FindType.FindByApplicationPolicy, "1.3.6.1.5.5.7.3.3", validOnly: false);
                }

                // Search!
                var query = pool;
                if (!string.IsNullOrEmpty(IssuerName))
                {
                    query = query.Find(X509FindType.FindByIssuerName, IssuerName, validOnly: false);
                }
                if (!string.IsNullOrEmpty(SubjectName))
                {
                    query = query.Find(X509FindType.FindBySubjectName, SubjectName, validOnly: false);
                }
                // Can't do RootName with the certificate collection
                if (!string.IsNullOrEmpty(Thumbprint))
                {
                    query = query.Find(X509FindType.FindByThumbprint, Thumbprint, validOnly: false);
                }

                if (AutoSelect)
                {
                    // Find the one with the longest validity and use it as the signing cert
                    var now = DateTime.Now;
                    return query
                        .Cast<X509Certificate2>()
                        .OrderByDescending(c => c.HasEKU(Constants.CodeSigningOid))
                        .OrderByDescending(c => c.NotAfter - now)
                        .FirstOrDefault();
                }
                else
                {
                    if (query.Count > 1)
                    {
                        AnsiConsole.Error.WriteLine(@"Multiple certificates were found that meet all the given
        criteria. Use the -a option to choose the best
        certificate automatically or use the -sha1 option with the hash of the
        desired certificate.");
                        AnsiConsole.Error.WriteLine("The following certificates meet all given criteria:");
                        foreach (var cert in query)
                        {
                            AnsiConsole.Error.WriteLine("    Issued to: " + cert.SubjectName.CommonName());
                            AnsiConsole.Error.WriteLine("    Issued by: " + cert.IssuerName.CommonName());
                            AnsiConsole.Error.WriteLine("    Expires:   " + cert.NotAfter.ToString("ddd MMM dd HH:mm:ss yyyy"));
                            AnsiConsole.Error.WriteLine("    SHA1 hash: " + cert.Thumbprint);
                            AnsiConsole.Error.WriteLine("");
                        }
                        return null;
                    }
                    else if (query.Count == 0)
                    {
                        return null;
                    }
                    return query[0];
                }
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
        }

        internal static SignOptions FromOptions(string fileName, IEnumerable<CommandOption> options)
        {
            var opts = new SignOptions()
            {
                FileName = fileName
            };
            foreach (var option in options)
            {
                Action<CommandOption, SignOptions> binder;
                if (_bindings.TryGetValue(option.LongName ?? option.ShortName, out binder))
                {
                    binder(option, opts);
                }
            }
            if (string.IsNullOrEmpty(opts.Output))
            {
                var extension = Path.GetExtension(fileName);

                // If the file is a signature request, change the extension
                if (string.Equals(extension, ".req", StringComparison.OrdinalIgnoreCase))
                {
                    opts.Output = Path.ChangeExtension(fileName, ".sig");
                }
                // Sometimes, we save signatures requests as ".sig" files, in those cases we replace the file in-place
                else if (string.Equals(extension, ".sig", StringComparison.OrdinalIgnoreCase))
                {
                    opts.Output = fileName;
                }
                // Otherwise, tack on ".sig" for the signature file
                else
                {
                    opts.Output = fileName + ".sig";
                }
            }
            return opts;
        }
    }
}