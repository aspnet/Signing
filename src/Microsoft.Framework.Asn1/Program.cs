using System;
using System.IO;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Asn1
{
    public class Program
    {
        public void Main(string[] args)
        {
            using (var fileStream = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.None))
            {
                var derParser = new BerParser();
                var result = derParser.Parse(fileStream);
                var visitor = new PrettyPrintingAsn1Visitor(AnsiConsole.Output.Writer, ansi: true);
                result.Accept(visitor);
            }
        }
    }
}
