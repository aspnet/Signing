using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;
using Microsoft.Framework.Signing.Native;

namespace Microsoft.Framework.Signing
{
    public class Program
    {
        public void Main(string[] args)
        {
#if NET45 || ASPNET50
            if (args.Length > 0 && string.Equals(args[0], "dbg", StringComparison.OrdinalIgnoreCase))
            {
                args = args.Skip(1).ToArray();
                System.Diagnostics.Debugger.Launch();
            }
#endif

            var app = new CommandLineApplication(throwOnUnexpectedArg: false);
            app.HelpOption("-h|--help");
            app.Command("timestamp", timestamp =>
            {
                timestamp.Description = "Timestamps an existing signature";
                var signature = timestamp.Argument("signature", "the path to the signature file");
                var authority = timestamp.Argument("url", "the path to a Authenticode trusted timestamping authority");
                timestamp.OnExecute(() => Timestamp(signature.Value, authority.Value));
            }, addHelpCommand: false);
            app.Command("sign", sign =>
            {
                sign.Description = "Signs a file";
                var fileName = sign.Argument("filename", "the name of the file to sign");
                var certificates = sign.Argument("certificates", "the path to a file containing certificates to sign with OR a value to search the certificate store for");
                var storeName = sign.Option("-sn|--storeName <storeName>", "the name of the certificate store to search for the certificate", CommandOptionType.SingleValue);
                var storeLocation = sign.Option("-sl|--storeLocation <storeLocation>", "the location of the certificate store to search for the certificate", CommandOptionType.SingleValue);
                var findType = sign.Option("-ft|--findType <x509findType>", "the criteria to search on (see http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509findtype(v=vs.110).aspx for example values)", CommandOptionType.SingleValue);
                var outputFile = sign.Option("-o|--output <outputFile>", "the path to the signature file to output (by default, the existing file name plus '.sig' is used)", CommandOptionType.SingleValue);
                var password = sign.Option("-p|--password <password>", "the password for the PFX file", CommandOptionType.SingleValue);
                sign.OnExecute(() => Sign(fileName.Value, certificates.Value, outputFile.Value(), password.Value(), storeName.Value(), storeLocation.Value(), findType.Value()));
            }, addHelpCommand: false);
            app.Command("verify", verify =>
            {
                verify.Description = "Verifies the signature of a file";
                var fileName = verify.Argument("filename", "the name of the file to verify");
                var signature = verify.Option("-s|--signature <signature>", "the path to the signature file to verify against (by default, the existing file name plus '.sig' is used)", CommandOptionType.SingleValue);
                verify.OnExecute(() => Verify(fileName.Value, signature.Value()));
            }, addHelpCommand: false);
            app.Command("help", help =>
            {
                help.Description = "Get help on the application, or a specific command";
                var command = help.Argument("command", "the command to get help on");
                help.OnExecute(() => { app.ShowHelp(command.Value); return 0; });
            }, addHelpCommand: false);
            app.OnExecute(() => { app.ShowHelp(commandName: null); return 0; });

            app.Execute(args);
        }

        private async Task<int> Timestamp(string signature, string authority)
        {
            // Open the signature and decode it
            byte[] data = PemFormatter.Unformat(File.ReadAllBytes(signature));

            // Load the NativeCms object
            byte[] digest;
            using (var cms = NativeCms.Decode(data, detached: true))
            {
                // Read the encrypted digest
                digest = cms.GetEncryptedDigest();
            }

            // Build the ASN.1 Timestamp Packet
            byte[] packet = Asn1Util.CreateTimestampRequest(digest);

            var client = new HttpClient();

            // Timestamp it!
            AnsiConsole.Output.WriteLine("Posting to timestamping server: " + authority);
            var content = new StringContent(Convert.ToBase64String(packet));
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            var response = await client.PostAsync(authority, content);
            if (!response.IsSuccessStatusCode)
            {
                AnsiConsole.Error.WriteLine("HTTP Error: " + response.StatusCode.ToString());
                return -1;
            }

            // Save the result
            var responsePacket = await response.Content.ReadAsStringAsync();
            var responseBytes = Convert.FromBase64String(responsePacket);
            File.WriteAllBytes(signature + ".ts", PemFormatter.Format(responseBytes, "TIMESTAMP"));

            return 0;
        }

        private async Task<int> Verify(string fileName, string signatureFile)
        {
            // Default values
            signatureFile = signatureFile ?? (fileName + ".sig");

            // Verify the signature
            var sig = await Signature.VerifyAsync(fileName, signatureFile);

            // Display the signature data
            AnsiConsole.Output.WriteLine("\x1b[32;1mSigner Information:\x1b[30;0m");
            AnsiConsole.Output.WriteLine("  \x1b[36;1m[Subject]\x1b[30;0m");
            AnsiConsole.Output.WriteLine("    " + sig.Signer.Subject);
            AnsiConsole.Output.WriteLine("  \x1b[36;1m[SPKI]\x1b[30;0m");
            AnsiConsole.Output.WriteLine("    " + sig.Signer.Spki);
            AnsiConsole.Output.WriteLine("  \x1b[36;1m[Issuer]\x1b[30;0m");
            AnsiConsole.Output.WriteLine("    " + sig.Signer.SignerCertificate.Issuer);

            // Check trust
            var trust = new TrustContext();
            var trustResult = trust.IsTrusted(sig);
            AnsiConsole.Output.WriteLine("");
            AnsiConsole.Output.WriteLine(string.Format("The file is {0}", trustResult.Trusted ? "TRUSTED" : "NOT TRUSTED"));
            foreach (var publisher in trustResult.TrustedPublishers)
            {
                AnsiConsole.Output.WriteLine("  Trusted by: " + publisher.Name);
                AnsiConsole.Output.WriteLine("    [SPKI] : " + publisher.Spki);
            }

            AnsiConsole.Output.WriteLine("");
            AnsiConsole.Output.WriteLine("");

            AnsiConsole.Output.WriteLine("Trust Chain:");
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(sig.Signer.Certificates);
            chain.Build(sig.Signer.SignerCertificate);
            foreach (var element in chain.ChainElements)
            {
                AnsiConsole.Output.WriteLine("  " + element.Certificate.Subject);
                AnsiConsole.Output.WriteLine("    Status: " + String.Join(", ", element.ChainElementStatus.Select(s => s.Status)));
                AnsiConsole.Output.WriteLine("    Info:   " + element.Information);
                AnsiConsole.Output.WriteLine("    SPKI:   " + element.Certificate.ComputePublicKeyIdentifier());
            }

            return 0;
        }

        private async Task<int> Sign(string fileName, string certificates, string outputFile, string password, string storeName, string storeLocation, string findType)
        {
            // Default values
            outputFile = outputFile ?? (fileName + ".sig");
            storeName = storeName ?? "My";
            storeLocation = storeLocation ?? "CurrentUser";
            findType = findType ?? "FindBySubjectName";

            // Get the certificates
            X509Certificate2 signingCert;
            X509Certificate2Collection certs;
            if (File.Exists(certificates))
            {
                certs = new X509Certificate2Collection();
                certs.Import(certificates, password, X509KeyStorageFlags.DefaultKeySet);
                if (certs.Count == 0)
                {
                    AnsiConsole.Error.WriteLine("Certificate file has no certificates: " + certificates);
                    return -1;
                }
                signingCert = new X509Certificate2(certificates, password);
            }
            else
            {
                StoreName name;
                if (!Enum.TryParse(storeName, ignoreCase: true, result: out name))
                {
                    AnsiConsole.Error.WriteLine("Unknown store name: " + storeName);
                    return -1;
                }

                StoreLocation loc;
                if (!Enum.TryParse(storeLocation, ignoreCase: true, result: out loc))
                {
                    AnsiConsole.Error.WriteLine("Unknown store location: " + storeLocation);
                    return -1;
                }

                X509FindType find;
                if (!Enum.TryParse(findType, ignoreCase: true, result: out find))
                {
                    AnsiConsole.Error.WriteLine("Unknown X509FindType: " + find);
                    return -1;
                }

                // Find the certificate in the store
                var store = new X509Store(name, loc);
                store.Open(OpenFlags.ReadOnly);
                certs = store.Certificates.Find(find, certificates, validOnly: false);
                if (certs.Count == 0)
                {
                    AnsiConsole.Error.WriteLine("Unable to find certificate using provided criteria");
                    return -1;
                }
                signingCert = certs[0];
            }

            // Make the signature
            var sig = await Signature.SignAsync(fileName, signingCert, certs);

            // Save the signature
            await sig.WriteAsync(outputFile);

            // Success!
            return 0;
        }
    }
}