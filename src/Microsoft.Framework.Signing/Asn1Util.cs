using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Framework.Signing
{
    internal static class Asn1Util
    {
        internal static byte[] CreateTimestampRequest(byte[] encryptedDigest)
        {
            // We're building this from the outside in using some manual DER-encoding hacking
            // Here's the full ASN.1 declaration for the Timestamp Request
            //  TimeStampRequest ::= SEQUENCE {
            //      countersignatureType OBJECT IDENTIFIER,
            //      attributes Attributes OPTIONAL, 
            //      contentInfo ContentInfo
            //  }
            // Attributes are omitted, they are optional and never actually provided.
            //
            //  ContentInfo ::= SEQUENCE {
            //      contentType ContentType,
            //      content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL 
            //  }
            //  ContentType ::= OBJECT IDENTIFIER
            //
            // ContentType will be PKCS#7 (https://tools.ietf.org/html/rfc2315) Data
            // Thus the content will be an ASN.1 OCTET STRING

            // Build the content info!
            //  Encode the OID: pkcs-7 1
            //   = 1.2.840.113549.1.7.1 (Decimal form)
            //   = 0x01 . 0x02 . (0x06 * 128) + 0x48 . (((0x06 * 128) + 0x77) * 128) + 0x0D . 0x01 . 0x07 . 0x01
            //   = 0x01 . 0x02 . 0x06 0x48 . 0x06 0x77 0x0D . 0x01 . 0x07 . 0x01 (Hex Base128 digits)
            //   = (40 * 0x01) + 0x02 . 0x06 0x48 . 0x06 0x77 0x0D . 0x01 . 0x07 . 0x01 (BER encoding combines the first two digits using (40*n1)+n2)
            //   = 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x01 (BER encodes multi-digit integers by setting bit 8 to 1 in all but the last digit of a value)
            //  Now just prepend the tag and length:
            //   = 0x06 0x09 [ 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x01 ]
            //  Confirmed encoding using ASN.1 JavaScript: http://lapo.it/asn1js/#06092A864886F70D010701
            var contentType = PrependBerHeader(
                tag: 0x06,
                value: new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 });

            // Build the content!
            //  The value is just an OCTET STRING, which is just the raw octets with a tag and length prepended:
            //   = 0x04 encryptedDigest.Length encryptedDigest
            //  Length has to be encoded in a special way
            var contentInner = PrependBerHeader(tag: 0x04, value: encryptedDigest);
            //  But it's wrapped in an explicit tag of 0 as well,
            //   = 0xA0 (contentInner.Length) contentInner
            var content = PrependBerHeader(tag: 0xA0, value: contentInner);

            // The ContentInfo value itself is a SEQUENCE, which is just a concatenation of
            // the member values, with a BER header using a tag of 0x30 (Constructed, SEQUENCE)
            var contentInfo = PrependBerHeader(
                tag: 0x30,
                value: Enumerable.Concat(contentType, content).ToArray());

            //  Encode the counter-signature type OID
            //   = 1.3.6.1.4.1.311.3.2.1
            //   = 0x01 . 0x03 . 0x06 . 0x01 . 0x04 . 0x01 . (0x02 * 128) + 0x37 . 0x03 . 0x02 . 0x01
            //   = 0x01 . 0x03 . 0x06 . 0x01 . 0x04 . 0x01 . 0x02 0x37 . 0x03 . 0x02 . 0x01 (Hex Base128 digits)
            //   = (40 * 0x01) + 0x03 . 0x06 . 0x01. 0x04. 0x01. 0x02 0x37 . 0x03 . 0x02 . 0x01 (BER encoding combines the first two digits using (40*n1)+n2)
            //   = 0x2B 0x06 0x01 0x04 0x01 0x82 0x37 0x03 0x02 0x01 (BER encodes multi-digit integers by setting bit 8 to 1 in all but the last digit of a value)
            //  Now just prepend the tag and length:
            //   = 0x06 0x0A [ 0x2B 0x06 0x01 0x04 0x01 0x82 0x37 0x03 0x02 0x01 ]
            //  Confirmed encoding using ASN.1 JavaScript: http://lapo.it/asn1js/#060A2B060104018237030201
            var counterSignatureType = PrependBerHeader(
                tag: 0x06,
                value: new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x02, 0x01 });

            // Finally! We just ignore the optional value and concat up a BER SEQUENCE encoding
            var requestPacket = PrependBerHeader(
                tag: 0x30,
                value: Enumerable.Concat(counterSignatureType, contentInfo).ToArray());

            return requestPacket;
        }

        private static byte[] PrependBerHeader(byte tag, byte[] value)
        {
            // Initialize the list with the tag
            IEnumerable<byte> octets = Single(tag);

            if (value.Length < 0x7F)
            {
                // It will fit in a single octet, so just add it
                octets = octets.Concat(Single((byte)(value.Length & 0x7F)));
            }
            else
            {
                // We need to format it into the long form
                //  First Octet: 0x80 + N (= Number of octets in the length)
                //  Remaining N Octets: Base 256 digits representing the length
                // Generate the list of digits in reverse order
                int len = value.Length;
                List<byte> lengthOctets = new List<byte>();
                do
                {
                    var digit = len % 256;
                    len = len / 256;

                    // Insert at the front so we "unreverse" the digits as we calculate them
                    lengthOctets.Insert(0, (byte)digit);
                } while (len > 256);

                // Prepend the first digit (which is the remainder of the length
                lengthOctets.Insert(0, (byte)len);

                // Calculate the first octet value and add it, then add the actual length octets
                octets = octets.Concat(Single((byte)(0x80 + (lengthOctets.Count & 0x7F))));
                octets = octets.Concat(lengthOctets);
            }

            return Enumerable.Concat(octets, value).ToArray();
        }

        private static IEnumerable<byte> Single(byte val)
        {
            yield return val;
        }
    }
}