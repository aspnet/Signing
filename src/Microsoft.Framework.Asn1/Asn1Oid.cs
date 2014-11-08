namespace Microsoft.Framework.Asn1
{
    public class Asn1Oid : Asn1Value
    {
        public string Oid { get; }

        public Asn1Oid(string oid) : this(Asn1Class.Universal, Asn1Constants.Tags.ObjectIdentifier, oid) { }

        public Asn1Oid(Asn1Class @class, int tag, string oid)
            : base(@class, tag)
        {
            Oid = oid;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}