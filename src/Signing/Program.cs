using System;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace PackageSigning
{
    public class Program
    {
        public void Main(string[] args)
        {
            var app = new CommandLineApplication(throwOnUnexpectedArg: false);
            app.HelpOption("-h|--help");
            app.Command("sign", sign =>
            {
                sign.Description = "Signs a file";
                var fileName = sign.Argument("filename", "the name of the file to sign");
                var certificates = sign.Argument("certificates", "the path to a PFX file containing certificates to sign with");
                var outputFile = sign.Option("-o|--output <outputFile>", "the path to the signature file to output (by default, the existing file name plus '.sig' is used)", CommandOptionType.SingleValue);
                var password = sign.Option("-p|--password <password>", "the password for the PFX file", CommandOptionType.SingleValue);
                sign.OnExecute(() => Sign(fileName.Value, certificates.Value, outputFile.Value(), password.Value()));
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

        private async Task<int> Sign(string fileName, string certificates, string outputFile, string password)
        {
            // Default values
            outputFile = outputFile ?? (fileName + ".sig");

            // Make the signature
            var sig = await Signature.SignAsync(fileName, certificates, password);

            // Save the signature
            await sig.WriteAsync(outputFile);

            // Success!
            return 0;
        }
    }
}