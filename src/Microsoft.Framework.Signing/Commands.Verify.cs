using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal partial class Commands
    {
        public async Task<int> Verify(string signatureFile, string targetFile, bool checkCertificates, bool skipRevocationCheck)
        {
            int exitCode = 0;

            // Verify the signature
            var sig = await Signature.TryDecodeAsync(signatureFile);

            var outConsole = AnsiConsole.GetOutput(false);
            var errConsole = AnsiConsole.GetError(false);
            // Display the signed files
            outConsole.WriteLine("Signature Payload");
            outConsole.WriteLine(" Version: " + sig.Payload.Version);
            outConsole.WriteLine(" Content Identifier: " + sig.Payload.ContentIdentifier);
            outConsole.WriteLine(" Digest Algorithm: " + sig.Payload.DigestAlgorithm.FriendlyName);
            outConsole.WriteLine(" Digest: " + BitConverter.ToString(sig.Payload.Digest).Replace("-", ""));

            // Check the payload?
            if (string.IsNullOrEmpty(targetFile))
            {
                targetFile = Path.Combine(Path.GetDirectoryName(signatureFile), sig.Payload.ContentIdentifier);
            }

            if (!File.Exists(targetFile))
            {
                errConsole.WriteLine(" Unable to locate content file for verification");
                exitCode = 1;
            }
            else if (sig.Payload.Verify(targetFile))
            {
                outConsole.WriteLine(" Content file matches digest!");
            }
            else
            {
                errConsole.WriteLine(" Content file does NOT match digest!");
                exitCode = 1;
            }

            // Display the signature data
            if (sig.IsSigned)
            {
                outConsole.WriteLine("");
                outConsole.WriteLine("Signer Information:");
                DumpSigner(sig, sig.Signatory);

                if (sig.IsTimestamped)
                {
                    outConsole.WriteLine("");
                    outConsole.WriteLine("Timestamper Information:");
                    outConsole.WriteLine(" Timestamped At (UTC  ): " + sig.Timestamp.TimestampUtc.ToString("O"));
                    outConsole.WriteLine(" Timestamped At (Local): " + sig.Timestamp.TimestampUtc.ToLocalTime().ToString("O"));
                    outConsole.WriteLine(" Policy ID: " + sig.Timestamp.TsaPolicyId);
                    outConsole.WriteLine(" Hash Algorithm: " + sig.Timestamp.HashAlgorithm);
                    DumpSigner(sig, sig.Timestamp.Signatory);
                }

                // Check the certificates against root trust (for now)
                if (checkCertificates)
                {
                    outConsole.WriteLine("");
                    outConsole.WriteLine("Signer Chain Status:");

                    X509Chain chain = new X509Chain();
                    chain.ChainPolicy.ExtraStore.AddRange(sig.Certificates);
                    if (skipRevocationCheck)
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    }
                    if (!chain.Build(sig.Signatory.SignerCertificate))
                    {
                        errConsole.WriteLine(" Signing Certificate is UNTRUSTED");
                        exitCode = 1;
                    }
                    else
                    {
                        outConsole.WriteLine(" Signing Certificate is TRUSTED");
                    }

                    if (chain.ChainStatus.Length > 0)
                    {
                        errConsole.WriteLine(" Certificate chain built with the following status messages:");
                        foreach (var status in chain.ChainStatus)
                        {
                            errConsole.WriteLine("  " + status.Status.ToString() + ": " + status.StatusInformation.Trim());
                        }
                        exitCode = 1;
                    }
                    else
                    {
                        outConsole.WriteLine(" Certificate chain built with no issues.");
                    }
                }
            }
            else
            {
                errConsole.WriteLine("");
                errConsole.WriteLine("NO signature found");
                exitCode = 2;
            }
            return exitCode;
        }

        private static string GetName(string digestAlgorithm)
        {
#if NET45
            Oid oid;
            try
            {
                oid = Oid.FromOidValue(digestAlgorithm, OidGroup.HashAlgorithm);
            }
            catch
            {
                return digestAlgorithm;
            }
            if (String.IsNullOrEmpty(oid.FriendlyName))
            {
                return digestAlgorithm;
            }
            return oid.FriendlyName;
#else
            return digestAlgorithm;
#endif
        }

        private static void DumpSigner(Signature signature, Signatory signer)
        {
            var outConsole = AnsiConsole.GetOutput(false);

            outConsole.WriteLine("  [Subject]");
            outConsole.WriteLine("    " + signer.SignerCertificate.Subject);
            outConsole.WriteLine("  [Issuer]");
            outConsole.WriteLine("    " + signer.SignerCertificate.Issuer);
            outConsole.WriteLine("  [SPKI]");
            outConsole.WriteLine("    " + signer.SignerCertificate.ComputePublicKeyIdentifier());
            outConsole.WriteLine("  [Signature Algorithm]");
            outConsole.WriteLine("    " + signer.SignerCertificate.SignatureAlgorithm.FriendlyName);
            outConsole.WriteLine("  [Signing Time]");
            outConsole.WriteLine("    " + (signer.SigningTime?.ToString("O")) ?? "UNKNOWN!");
            outConsole.WriteLine("  [Cert Chain]");
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(signature.Certificates);
            chain.Build(signer.SignerCertificate);
            foreach (var element in chain.ChainElements)
            {
                outConsole.WriteLine("    " + element.Certificate.Subject);
                outConsole.WriteLine("      Issued By: " + element.Certificate.IssuerName.CommonName());
                outConsole.WriteLine("      Status: " + String.Join(", ", element.ChainElementStatus.Select(s => s.Status)));
                outConsole.WriteLine("      Info:   " + element.Information);
                outConsole.WriteLine("      SPKI:   " + element.Certificate.ComputePublicKeyIdentifier());
            }
        }
    }
}