using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal static partial class Commands
    {
        public static async Task<int> Sign(string fileName, IEnumerable<CommandOption> options)
        {
            var signOptions = SignOptions.FromOptions(fileName, options);

            X509Certificate2Collection includedCerts;
            var signingCert = signOptions.FindCert(out includedCerts);
            if (signingCert == null)
            {
                AnsiConsole.Error.WriteLine("Unable to find certificate that meets the specified criteria");
                return 1;
            }
            AnsiConsole.Output.WriteLine("Signing file with: " + signingCert.SubjectName.CommonName());

            // Load the private key if provided
            if (!string.IsNullOrEmpty(signOptions.CspName) && !string.IsNullOrEmpty(signOptions.KeyContainer))
            {
                var parameters = new CspParameters()
                {
                    ProviderType = 1, // PROV_RSA_FULL
                    KeyNumber = (int)KeyNumber.Signature,
                    ProviderName = signOptions.CspName,
                    KeyContainerName = signOptions.KeyContainer
                };
                signingCert.PrivateKey = new RSACryptoServiceProvider(parameters);
            }

            if (!signingCert.HasPrivateKey)
            {
                AnsiConsole.Error.WriteLine("Unable to find private key for certificate: " + signingCert.SubjectName.CommonName());
                return 1;
            }

            // If the input file didn't provide any additional certs, set up a new collection
            var additionalCerts = new X509Certificate2Collection();

            // Load any additional certs requested by the user
            if (!string.IsNullOrEmpty(signOptions.AddCertificatesFile))
            {
                additionalCerts.Import(signOptions.AddCertificatesFile);
            }

            // Determine if we are signing a request or a file
            Signature sig = await Signature.TryDecodeAsync(fileName);
            if (sig == null)
            {
                sig = new Signature(SignaturePayload.Compute(fileName, Signature.DefaultDigestAlgorithmName));
            }

            // Verify that the content is unsigned
            if (sig.IsSigned)
            {
                AnsiConsole.Error.WriteLine("File already signed: " + fileName);
                return 1;
            }

            // Sign the file
            sig.Sign(signingCert, includedCerts, additionalCerts);

            AnsiConsole.Output.WriteLine("Successfully signed.");

            if (!string.IsNullOrEmpty(signOptions.Timestamper))
            {
                // Timestamp the signature
                AnsiConsole.Output.WriteLine("Transmitting signature to timestamping authority...");
                sig.Timestamp(new Uri(signOptions.Timestamper), signOptions.TimestamperAlgorithm ?? Signature.DefaultDigestAlgorithmName);
                AnsiConsole.Output.WriteLine("Trusted timestamp applied to signature.");
            }

            // Write the signature
            AnsiConsole.Output.WriteLine("Signature saved to " + signOptions.Output);
            await sig.WriteAsync(signOptions.Output);

            return 0;
        }
    }
}