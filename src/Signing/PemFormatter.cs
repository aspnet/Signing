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

            string base64 = Convert.ToBase64String(rawData);
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < base64.Length; i += 64)
            {
                var len = Math.Min(64, base64.Length - i);
                builder.AppendLine(base64.Substring(i, len));
            }

            return Encoding.UTF8.GetBytes(
                String.Format(
                    "-----{0}-----{1}{2}-----{3}-----",
                    header,
                    Environment.NewLine,
                    builder.ToString(),
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