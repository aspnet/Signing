using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Asn1;
using Microsoft.Framework.Runtime.Common.CommandLine;
using Microsoft.Framework.Signing.Native;

namespace Microsoft.Framework.Signing
{
    public class Program
    {
        private static readonly IList<string> TimestampServers = new List<string>()
        {
            "http://timestamp.digicert.com",
            "http://timestamp.comodoca.com/authenticode",
            "http://tsa.starfieldtech.com/"
        };

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
            app.Command("sigreq", sigreq =>
            {
                sigreq.Description = "Creates a signing request for the specific file";
                var fileName = sigreq.Argument(
                    "filename", 
                    "the name of the file to create a signature request for");
                var outputFile = sigreq.Option(
                    "-o|--output", 
                    "the name of the signature request file to create (defaults to the input filename with the '.sigreq' extension added)", 
                    CommandOptionType.SingleValue);
                var digestAlgorithm = sigreq.Option(
                    "-alg|--algorithm", 
                    "the name of the digest algorithm to use", 
                    CommandOptionType.SingleValue);
                sigreq.OnExecute(() =>
                    Commands.CreateSigningRequest(
                        fileName.Value,
                        outputFile.Value(),
                        digestAlgorithm.Value()));
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
                sign.OnExecute(() => Commands.Sign(fileName.Value, certificates.Value, outputFile.Value(), password.Value(), storeName.Value(), storeLocation.Value(), findType.Value()));
            }, addHelpCommand: false);
            app.Command("view", view =>
            {
                view.Description = "Views a signature file";
                var fileName = view.Argument("filename", "the name of the signature file to view");
                view.OnExecute(() => Commands.View(fileName.Value));
            }, addHelpCommand: false);

            //app.Command("timestamp", timestamp =>
            //{
            //    timestamp.Description = "Timestamps an existing signature";
            //    var signature = timestamp.Argument("signature", "the path to the signature file");
            //    var authority = timestamp.Argument("url", "the path to a Authenticode trusted timestamping authority");
            //    timestamp.OnExecute(() => Timestamp(signature.Value, authority.Value));
            //}, addHelpCommand: false);
            //app.Command("sign", sign =>
            app.Command("help", help =>
            {
                help.Description = "Get help on the application, or a specific command";
                var command = help.Argument("command", "the command to get help on");
                help.OnExecute(() => { app.ShowHelp(command.Value); return 0; });
            }, addHelpCommand: false);
            app.OnExecute(() => { app.ShowHelp(commandName: null); return 0; });

            app.Execute(args);
        }

        //private async Task<int> Timestamp(string signature, string authority)
        //{
        //    // Open the signature and decode it
        //    byte[] data = PemFormatter.Unformat(File.ReadAllBytes(signature));

        //    // Load the NativeCms object
        //    byte[] digest;
        //    using (var cms = NativeCms.Decode(data, detached: true))
        //    {
        //        // Read the encrypted digest
        //        digest = cms.GetEncryptedDigest();

        //        // Build the ASN.1 Timestamp Packet
        //        var req = new Asn1Sequence(                     //  TimeStampRequest ::= SEQUENCE {
        //            Asn1Oid.Parse("1.3.6.1.4.1.311.3.2.1"),     //      countersignatureType
        //                                                        //      attributes (none)
        //            new Asn1Sequence(                           //      contentInfo ::= SEQUENCE {
        //                Asn1Oid.Parse("1.2.840.113549.1.7.1"),  //          contentType
        //                new Asn1ExplicitTag(tag: 0,             //          content
        //                    value: new Asn1OctetString(digest))));

        //        var packet = DerEncoder.Encode(req);

        //        var client = new HttpClient();

        //        // Timestamp it!
        //        AnsiConsole.Output.WriteLine("Posting to timestamping server: " + authority);
        //        var content = new StringContent(Convert.ToBase64String(packet));
        //        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        //        var response = await client.PostAsync(authority, content);
        //        if (!response.IsSuccessStatusCode)
        //        {
        //            AnsiConsole.Error.WriteLine("HTTP Error: " + response.StatusCode.ToString());
        //            return -1;
        //        }

        //        var resp = await response.Content.ReadAsStringAsync();
        //        AnsiConsole.Output.WriteLine("Response: HTTP " + (int)response.StatusCode + " " + response.ReasonPhrase);

        //        // Load the result into a NativeCms
        //        var respBytes = Convert.FromBase64String(resp);
        //        byte[] signerInfo;
        //        IEnumerable<byte[]> certs;
        //        using (var timestampCms = NativeCms.Decode(respBytes, detached: true))
        //        {
        //            // Read the signerinfo and certificates
        //            signerInfo = timestampCms.GetEncodedSignerInfo();

        //            certs = timestampCms.GetCertificates();
        //        }

        //        // Write the certs into the cms
        //        cms.AddCertificates(certs);

        //        // Write the signer
        //        cms.AddCountersignature(signerInfo);

        //        // Read the new message and dump it!
        //        var encoded = cms.Encode();
        //        File.WriteAllBytes(
        //            signature,
        //            PemFormatter.Format(encoded, "BEGIN SIGNATURE", "END SIGNATURE"));
        //    }

        //    return 0;
        //}
    }
}