namespace Microsoft.Framework.Asn1
{
    public static class Asn1Constants
    {
        public static class Tags
        {
            public static readonly int Integer = 0x02;
            public static readonly int BitString = 0x03;
            public static readonly int OctetString = 0x04;
            public static readonly int Null = 0x05;
            public static readonly int ObjectIdentifier = 0x06;
            public static readonly int Sequence = 0x10;
            public static readonly int Set = 0x11;
            public static readonly int PrintableString = 0x13;
            public static readonly int T61String = 0x14;
            public static readonly int IA5String = 0x16;
            public static readonly int UTCTime = 0x17;
        }
    }
}