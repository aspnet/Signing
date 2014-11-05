using System;
using System.Text;
using System.Text.RegularExpressions;

namespace PackageSigning
{
    internal static class PemFormatter
    {
        public static byte[] Format(byte[] rawData, string header = null, string footer = null)
        {
            header = header ?? "PEM";
            footer = footer ?? header;
            return Encoding.UTF8.GetBytes(
                String.Format(
                    "-----{0}-----{1}{2}{1}-----{3}-----",
                    header,
                    Environment.NewLine,
                    Convert.ToBase64String(rawData),
                    footer));

        }

        private static readonly Regex PemParser = new Regex(@"\-*[^\-]*\-*(?<data>.*)\-*[^\-]*\-*");
        public static byte[] Unformat(byte[] pemData)
        {
            string data = Encoding.UTF8.GetString(pemData);
            var match = PemParser.Match(data);
            if (!match.Success)
            {
                throw new FormatException("Invalid PEM file!");
            }
            return Convert.FromBase64String(
                match.Groups["data"].Value.Replace("\r", "").Replace("\n", ""));
        }
    }
}