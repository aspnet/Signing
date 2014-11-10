using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Null : Asn1Value
    {
        public static readonly Asn1Null Instance = new Asn1Null();

        private Asn1Null() : base(Asn1Class.Universal, Asn1Constants.Tags.Null) { }

        public override string ToString()
        {
            return base.ToString() + " NULL";
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1Null other = obj as Asn1Null;
            return other != null && base.Equals(other);
        }

        public override int GetHashCode()
        {
            // Base hash-code is unique enough!
            return base.GetHashCode();
        }
    }
}