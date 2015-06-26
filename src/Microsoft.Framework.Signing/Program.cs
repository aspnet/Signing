using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime;
using Microsoft.Framework.Runtime.Common.CommandLine;
using Microsoft.Framework.Signing.Native;

namespace Microsoft.Framework.Signing
{
    public class Program
    {
        private IApplicationEnvironment _env;

        public Program(IApplicationEnvironment env)
        {
            _env = env;
        }

        public int Main(string[] args)
        {
            try
            {
#if NET45 || DNX451
                if (args.Length > 0 && string.Equals(args[0], "dbg", StringComparison.OrdinalIgnoreCase))
                {
                    args = args.Skip(1).ToArray();
                    System.Diagnostics.Debugger.Launch();
                }
#endif

                var app = new CommandLineApplication(throwOnUnexpectedArg: false);
                app.Name = "ksigntool";
                app.Description = "Signing tool for NuGet/ASP.Net 5 Packages";
                app.HelpOption("-h|--help");
                app.VersionOption("-v|--version", String.Format("{0} {1} (Runtime: {2}; Configuration: {3})", app.Name, _env.Version, _env.RuntimeFramework, _env.Configuration));

                var commands = new Commands(new Signer());

                app.Command("prepare", prepare =>
                {
                    prepare.Description = "Creates a signing request for the specific file";
                    var fileName = prepare.Argument(
                        "filename",
                        "the name of the file to create a signature request for");
                    var outputFile = prepare.Option(
                        "-o|--output",
                        "the name of the signature request file to create (defaults to the input filename with the '.sigreq' extension added)",
                        CommandOptionType.SingleValue);
                    var digestAlgorithm = prepare.Option(
                        "-alg|--algorithm",
                        "the name of the digest algorithm to use",
                        CommandOptionType.SingleValue);
                    prepare.OnExecute(() =>
                        commands.Prepare(
                            fileName.Value,
                            outputFile.Value(),
                            digestAlgorithm.Value()));
                });

                app.Command("sign", sign =>
                {
                    sign.Description = "Signs a file";
                    var fileName = sign.Argument("filename", "the name of the file to sign");

                    sign.Option("-a|--auto-select", "select the best signing cert automatically (the one valid for the longest time from now)", CommandOptionType.NoValue);
                    sign.Option("-f|--file <certificateFile>", "the path to a file containing certificates to sign with", CommandOptionType.SingleValue);
                    sign.Option("-ac|--add-certs <addCertificatesFile>", "add additional certficiates from <certificatesFile> to the signature block", CommandOptionType.SingleValue);

                    sign.Option("-i|--issuer <issuerName>", "specify the Issuer of the signing cert, or a substring", CommandOptionType.SingleValue);
                    sign.Option("-n|--subject <subjectName>", "specify the Subject Name of the signing cert, or a substring", CommandOptionType.SingleValue);
                    sign.Option("-p|--password <password>", "the password for the file specified by <certificateFile>", CommandOptionType.SingleValue);
                    sign.Option("-s|--store <storeName>", "specify the Store to open when searching for the cert (defaults to the 'My' Store)", CommandOptionType.SingleValue);
                    sign.Option("-sm|--machine-store", "open a machine Store instead of a user Store", CommandOptionType.SingleValue);
                    sign.Option("-sha1|--thumbprint <certhash>", "specifies the SHA1 thumbprint of the certificate to use to sign the file", CommandOptionType.SingleValue);

                    sign.Option("-csp|--key-provider <cspname>", "specify the CSP containing the Private Key Container", CommandOptionType.SingleValue);
                    sign.Option("-kc|--key-container <containername>", "specify the Key Container Name of the Private Key", CommandOptionType.SingleValue);

                    sign.Option("-o|--output <outputFile>", "the path to the signature file to output (by default, the existing file name plus '.sig' is used)", CommandOptionType.SingleValue);

                    sign.Option("-t|-tr|--timestamper <timestampAuthorityUrl>", "a URL to an RFC3161-compliant timestamping authority to timestamp the signature with", CommandOptionType.SingleValue);
                    sign.Option("-td|--timestamper-algorithm <algorithmName>", "the name of the hash algorithm to use for the timestamp", CommandOptionType.SingleValue);

                    sign.OnExecute(() => commands.Sign(fileName.Value, sign.Options));
                });

                app.Command("timestamp", timestamp =>
                {
                    timestamp.Description = "Timestamps an existing signature";
                    var signature = timestamp.Argument("signature", "the path to the signature file");
                    var authority = timestamp.Argument("url", "the path to a Authenticode trusted timestamping authority");
                    var algorithm = timestamp.Option("-alg|--algorithm <algorithmName>", "the name of the hash algorithm to use for the timestamp", CommandOptionType.SingleValue);
                    timestamp.OnExecute(() => commands.Timestamp(signature.Value, authority.Value, algorithm.Value()));
                });

                app.Command("verify", verify =>
                {
                    verify.Description = "Verifies a signature file";
                    var fileName = verify.Argument("filename", "the name of the signature file to view");
                    var noCheckCerts = verify.Option("-nocerts|--ignore-certificate-errors", "set this switch to ignore errors caused by untrusted certificates", CommandOptionType.NoValue);
                    var skipRevocation = verify.Option("-norevoke|--skip-revocation-check", "set this switch to ignore revocation check failures", CommandOptionType.NoValue);
                    var targetFile = verify.Option("-t|--target-file <targetFile>", "check the signature against <targetFile> (usually read from signature data)", CommandOptionType.SingleValue);
                    verify.OnExecute(() => commands.Verify(fileName.Value, targetFile.Value(), !noCheckCerts.HasValue(), skipRevocation.HasValue()));
                });

                app.Command("help", help =>
                {
                    help.Description = "Get help on the application, or a specific command";
                    var command = help.Argument("command", "the command to get help on");
                    help.OnExecute(() => { app.ShowHelp(command.Value); return 0; });
                });
                app.OnExecute(() => { app.ShowHelp(commandName: null); return 0; });

                return app.Execute(args);
            }
            catch(Exception ex)
            {
                AnsiConsole.Error.WriteLine(ex.ToString());
                return 1;
            }
        }
    }
}
