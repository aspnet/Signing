using System;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    public class Asn1OctetString : Asn1Value
    {
        public byte[] Value { get; }

        public Asn1OctetString(byte[] value)
            : this(Asn1Class.Universal, Asn1Constants.Tags.OctetString, value)
        {
        }

        public Asn1OctetString(Asn1Class @class, int tag, byte[] value)
            : base(@class, tag)
        {
            Value = value;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1OctetString other = obj as Asn1OctetString;
            return other != null &&
                base.Equals(other) &&
                Enumerable.SequenceEqual(Value, other.Value);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Value);
        }

        public override string ToString()
        {
            return base.ToString() + " OCTET STRING " + Value.Length + " bytes long";
        }
    }
}