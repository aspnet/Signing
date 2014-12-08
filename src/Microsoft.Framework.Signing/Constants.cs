using System;
using System.Security.Cryptography;

namespace Microsoft.Framework.Signing
{
    internal static class Constants
    {
        public static readonly Oid CodeSigningOid = new Oid("1.3.6.1.5.5.7.3.3");

        // From RFC5126 (CAdES) spec: http://tools.ietf.org/html/rfc5126#section-6.1.1
        public static readonly Oid SignatureTimeStampTokenAttributeOid = new Oid("1.2.840.113549.1.9.16.2.14");
    }
}