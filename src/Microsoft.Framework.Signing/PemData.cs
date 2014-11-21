using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Microsoft.Framework.Signing
{
    public class PemData
    {
        private static readonly Regex PemBarrierRegex = new Regex(@"^\-+(?<name>[A-Za-z0-9\s]+)\-+$");

        public string Header { get; }
        public byte[] Data { get; }
        public string Footer { get; }

        public PemData(string header, byte[] data, string footer)
        {
            Header = header;
            Data = data;
            Footer = footer;
        }

        public static async Task<PemData> TryDecodeAsync(Stream stream)
        {
            using (var reader = new StreamReader(stream))
            {
                return await TryDecodeAsync(reader);
            }
        }

        public byte[] Encode()
        {
            string base64 = Convert.ToBase64String(Data);
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < base64.Length; i += 64)
            {
                var len = Math.Min(64, base64.Length - i);
                builder.AppendLine(base64.Substring(i, len));
            }

            return Encoding.UTF8.GetBytes(
                String.Format(
                    "-----{0}-----{1}{2}-----{3}-----",
                    Header,
                    Environment.NewLine,
                    builder.ToString(),
                    Footer));
        }

        public static async Task<PemData> TryDecodeAsync(TextReader input)
        {
            // Read the header
            var header = GetBarrierName(await input.ReadLineAsync());
            if (header == null)
            {
                return null;
            }

            // Read the data
            List<string> dataLines = new List<string>();
            string line;
            while (!(line = await input.ReadLineAsync()).StartsWith("-"))
            {
                dataLines.Add(line);
            }
            byte[] data;
            try
            {
                data = Convert.FromBase64String(String.Concat(dataLines));
            }
            catch
            {
                return null; // Invalid Base64 String!
            }

            // Read the footer
            var footer = GetBarrierName(line);
            return new PemData(header, data, footer);
        }

        private static string GetBarrierName(string barrier)
        {
            var match = PemBarrierRegex.Match(barrier);
            if (!match.Success)
            {
                return null; // Not valid PEM
            }
            return match.Groups["name"].Value;
        }

        //public static byte[] Format(byte[] rawData, string header = null, string footer = null)
        //{


        //}

        //private static readonly Regex PemParser = new Regex(@"^(\-+[^\-]+\-+)\s*(?<data>[^\-]+)\s*(\-+[^\-]+\-+)$");
        //public static byte[] Unformat(byte[] pemData)
        //{
        //    byte[] unformatted;
        //    if (!TryUnformat(pemData, out unformatted))
        //    {
        //        throw new FormatException("Invalid PEM file!");
        //    }
        //}

        //public static bool TryUnformat(byte[] pemData, out byte[] unformatted)
        //{
        //    unformatted = null;

        //    string data = Encoding.UTF8.GetString(pemData);
        //    var match = PemParser.Match(data);
        //    if (!match.Success)
        //    {
        //        return false;
        //    }
        //    string base64 = match.Groups["data"].Value.Replace("\r", "").Replace("\n", "");
        //    unformatted = Convert.FromBase64String(base64);
        //    return true;
        //}
    }
}