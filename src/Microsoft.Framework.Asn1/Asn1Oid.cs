using System.Security.Cryptography;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Oid : Asn1Value
    {
        public string Oid { get; }

        public Asn1Oid(Asn1Class @class, int tag, int length, Asn1Encoding encoding, string oid)
            : base(@class, tag, length, encoding)
        {
            Oid = oid;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}