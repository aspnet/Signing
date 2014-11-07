using System;
using System.Linq;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace Microsoft.Framework.Signing
{
    internal static class DumpCms
    {
        private static Dictionary<string, string> _otherOidNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["1.3.6.1.4.1.311.2.1.12"] = "SPC_SP_OPUS_INFO_OBJID",
            ["1.3.6.1.4.1.311.2.1.11"] = "SPC_STATEMENT_TYPE_OBJID",
        };

        public static int Main(bool isPem, string fileName)
        {
            var cms = ReadSignature(isPem, fileName);

            Console.WriteLine("--- SIGNATURE ---");

            Console.WriteLine("  [Version] " + cms.Version);
            Console.WriteLine("  [Content Info] ");
            Console.WriteLine("    Type: " + FormatOid(cms.ContentInfo.ContentType));

            Console.WriteLine("  [Signer]");
            WriteSigner(cms.SignerInfos.Cast<SignerInfo>().FirstOrDefault(), level: 0);

            Console.WriteLine("--- END SIGNATURE ---");
            return 0;
        }

        internal static int ExtractContent(bool isPem, string source, string dest)
        {
            var cms = ReadSignature(isPem, source);
            File.WriteAllBytes(dest, cms.ContentInfo.Content);
            return 0;
        }

        private static SignedCms ReadSignature(bool isPem, string fileName)
        {
            var data = File.ReadAllBytes(fileName);
            if (isPem)
            {
                // Decode the pem file
                data = PemFormatter.Unformat(data);
            }

            var cms = new SignedCms();
            cms.Decode(data);
            return cms;
        }

        private static void WriteSigner(SignerInfo signer, int level)
        {
            var indent = "    " + new string(' ', level * 4);
            Console.WriteLine(indent + "[Version] " + signer.Version);
            Console.WriteLine(indent + "[Signer Identifier]");
            WriteSignerId(indent + "  ", signer.SignerIdentifier);
            Console.WriteLine(indent + "[Digest Algorithm]");
            Console.WriteLine(indent + "  " + FormatOid(signer.DigestAlgorithm));
            var certStr = signer.Certificate.ToString();
            foreach (var line in certStr.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries))
            {
                Console.WriteLine(indent + line);
            }

            Console.WriteLine(indent + "[Signed Attributes]");
            WriteAttributes(indent, signer.SignedAttributes);
            Console.WriteLine(indent + "[Unsigned Attributes]");
            WriteAttributes(indent, signer.UnsignedAttributes);

            var counterSigners = signer.CounterSignerInfos.Cast<SignerInfo>();
            if (counterSigners.Any())
            {
                Console.WriteLine(indent + "[Counter Signers]");
                foreach (var counterSigner in counterSigners)
                {
                    Console.WriteLine(indent + "  [Counter Signer]");
                    WriteSigner(counterSigner, level: level + 1);
                }
            }
        }

        private static void WriteSignerId(string indent, SubjectIdentifier signerId)
        {
            Console.WriteLine(indent + signerId.Type);

            switch (signerId.Type)
            {
                case SubjectIdentifierType.IssuerAndSerialNumber:
                    Console.WriteLine(indent + "Iss: " + ((X509IssuerSerial)signerId.Value).IssuerName);
                    Console.WriteLine(indent + "Ser: " + ((X509IssuerSerial)signerId.Value).SerialNumber);
                    break;
                case SubjectIdentifierType.SubjectKeyIdentifier:
                    Console.WriteLine(indent + "Ski: " + (string)signerId.Value);
                    break;
                case SubjectIdentifierType.NoSignature:
                    Console.WriteLine(indent + "<<NONE>>");
                    break;
                default:
                    Console.WriteLine(indent + signerId.Value.GetType().FullName);
                    break;
            }
        }

        private static void WriteAttributes(string indent, CryptographicAttributeObjectCollection attrs)
        {
            foreach (var signedAttr in attrs)
            {
                Console.WriteLine(indent + "  " + FormatOid(signedAttr.Oid));
                foreach (var value in signedAttr.Values)
                {
                    var contentType = value as Pkcs9ContentType;
                    if (contentType != null)
                    {
                        Console.WriteLine(indent + "    " + FormatOid(contentType.ContentType));
                    }
                    else
                    {
                        var digest = value as Pkcs9MessageDigest;
                        if (digest != null)
                        {
                            Console.WriteLine(indent + "    [" + Truncate(BitConverter.ToString(digest.MessageDigest).Replace("-", ""), maxLen: 64) + "]");
                        }
                        else
                        {
                            var signingTime = value as Pkcs9SigningTime;
                            if (signingTime != null)
                            {
                                Console.WriteLine(indent + "    Signed At: " + signingTime.SigningTime.ToLocalTime().ToString("O"));
                            }
                            else
                            {
                                Console.WriteLine(indent + "    " + value.GetType().Name);
                            }
                        }
                    }
                }
            }
        }

        private static string Truncate(string str, int maxLen)
        {
            if (str.Length > maxLen)
            {
                return str.Substring(0, maxLen - 3) + "...";
            }
            return str;
        }

        private static string FormatOid(Oid oid)
        {
            var friendlyName = oid.FriendlyName;
            if (friendlyName == null && !_otherOidNames.TryGetValue(oid.Value, out friendlyName))
            {
                friendlyName = "UNKNOWN";
            }
            return friendlyName + " (" + oid.Value + ")";
        }
    }
}