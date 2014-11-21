using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal static partial class Commands
    {
        public static async Task<int> Sign(string fileName, string certificates, string outputFile, string password, string storeName, string storeLocation, string findType)
        {
            // Default values
            if (String.IsNullOrEmpty(outputFile))
            {
                if (string.Equals(Path.GetExtension(fileName), ".sigreq", StringComparison.OrdinalIgnoreCase))
                {
                    outputFile = Path.ChangeExtension(fileName, ".sig");
                }
                else
                {
                    outputFile = fileName + ".sig";
                }
            }
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

            // Determine if we are signing a request or a file
            Signature sig = await Signature.TryDecodeAsync(fileName);
            if (sig == null)
            {
                sig = new Signature(SignatureEntry.Compute(fileName, Signature.DefaultDigestAlgorithmName));
            }

            // Verify that the content is unsigned
            if (sig.IsSigned)
            {
                AnsiConsole.Error.WriteLine("File already signed: " + fileName);
                return -1;
            }

            // Sign the file
            sig.Sign(signingCert, certs);

            // Write the signature
            await sig.WriteAsync(outputFile);

            return 0;
        }
    }
}