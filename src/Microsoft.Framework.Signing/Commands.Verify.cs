using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal static partial class Commands
    {
        public static async Task<int> Verify(string signatureFile, string targetFile, bool checkCertificates, bool skipRevocationCheck)
        {
            int exitCode = 0;

            // Verify the signature
            var sig = await Signature.TryDecodeAsync(signatureFile);

            // Display the signed files
            AnsiConsole.Output.WriteLine("Signature Payload");
            AnsiConsole.Output.WriteLine(" Version: " + sig.Payload.Version);
            AnsiConsole.Output.WriteLine(" Content Identifier: " + sig.Payload.ContentIdentifier);
            AnsiConsole.Output.WriteLine(" Digest Algorithm: " + sig.Payload.DigestAlgorithm.FriendlyName);
            AnsiConsole.Output.WriteLine(" Digest: " + BitConverter.ToString(sig.Payload.Digest).Replace("-", ""));

            // Check the payload?
            if (string.IsNullOrEmpty(targetFile))
            {
                targetFile = Path.Combine(Path.GetDirectoryName(signatureFile), sig.Payload.ContentIdentifier);
            }

            if (!File.Exists(targetFile))
            {
                AnsiConsole.Error.WriteLine(" Unable to locate content file for verification");
                exitCode = 1;
            }
            else if (sig.Payload.Verify(targetFile))
            {
                AnsiConsole.Output.WriteLine(" Content file matches digest!");
            }
            else
            {
                AnsiConsole.Error.WriteLine(" Content file does NOT match digest!");
                exitCode = 1;
            }

            // Display the signature data
            if (sig.IsSigned)
            {
                AnsiConsole.Output.WriteLine("");
                AnsiConsole.Output.WriteLine("Signer Information:");
                DumpSigner(sig, sig.Signer);

                if (sig.IsTimestamped)
                {
                    AnsiConsole.Output.WriteLine("");
                    AnsiConsole.Output.WriteLine("Timestamper Information:");
                    AnsiConsole.Output.WriteLine(" Timestamped At (UTC  ): " + sig.Timestamper.TimestampUtc.ToString("O"));
                    AnsiConsole.Output.WriteLine(" Timestamped At (Local): " + sig.Timestamper.TimestampUtc.ToLocalTime().ToString("O"));
                    AnsiConsole.Output.WriteLine(" Policy ID: " + sig.Timestamper.TsaPolicyId);
                    AnsiConsole.Output.WriteLine(" Hash Algorithm: " + sig.Timestamper.HashAlgorithm);
                    DumpSigner(sig, sig.Timestamper.Signer);
                }

                // Check the certificates against root trust (for now)
                if (checkCertificates)
                {
                    AnsiConsole.Output.WriteLine("");
                    AnsiConsole.Output.WriteLine("Signer Chain Status:");

                    X509Chain chain = new X509Chain();
                    chain.ChainPolicy.ExtraStore.AddRange(sig.Certificates);
                    if (skipRevocationCheck)
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    }
                    if (!chain.Build(sig.Signer.SignerCertificate))
                    {
                        AnsiConsole.Error.WriteLine(" Signing Certificate is UNTRUSTED");
                        exitCode = 1;
                    }
                    else
                    {
                        AnsiConsole.Output.WriteLine(" Signing Certificate is TRUSTED");
                    }

                    if (chain.ChainStatus.Length > 0)
                    {
                        AnsiConsole.Error.WriteLine(" Certificate chain built with the following status messages:");
                        foreach (var status in chain.ChainStatus)
                        {
                            AnsiConsole.Error.WriteLine("  " + status.Status.ToString() + ": " + status.StatusInformation.Trim());
                        }
                        exitCode = 1;
                    }
                    else
                    {
                        AnsiConsole.Output.WriteLine(" Certificate chain built with no issues.");
                    }
                }
            }
            else
            {
                AnsiConsole.Error.WriteLine("");
                AnsiConsole.Error.WriteLine("NO signature found");
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

        private static void DumpSigner(Signature signature, Signer signer)
        {
            AnsiConsole.Output.WriteLine("  [Subject]");
            AnsiConsole.Output.WriteLine("    " + signer.SignerCertificate.Subject);
            AnsiConsole.Output.WriteLine("  [Issuer]");
            AnsiConsole.Output.WriteLine("    " + signer.SignerCertificate.Issuer);
            AnsiConsole.Output.WriteLine("  [SPKI]");
            AnsiConsole.Output.WriteLine("    " + signer.Spki);
            AnsiConsole.Output.WriteLine("  [Signature Algorithm]");
            AnsiConsole.Output.WriteLine("    " + signer.SignerCertificate.SignatureAlgorithm.FriendlyName);
            AnsiConsole.Output.WriteLine("  [Signing Time]");
            AnsiConsole.Output.WriteLine("    " + (signer.SigningTime?.ToString("O")) ?? "UNKNOWN!");
            AnsiConsole.Output.WriteLine("  [Cert Chain]");
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(signature.Certificates);
            chain.Build(signer.SignerCertificate);
            foreach (var element in chain.ChainElements)
            {
                AnsiConsole.Output.WriteLine("    " + element.Certificate.Subject);
                AnsiConsole.Output.WriteLine("      Issued By: " + element.Certificate.IssuerName.CommonName());
                AnsiConsole.Output.WriteLine("      Status: " + String.Join(", ", element.ChainElementStatus.Select(s => s.Status)));
                AnsiConsole.Output.WriteLine("      Info:   " + element.Information);
                AnsiConsole.Output.WriteLine("      SPKI:   " + element.Certificate.ComputePublicKeyIdentifier());
            }
        }
    }
}