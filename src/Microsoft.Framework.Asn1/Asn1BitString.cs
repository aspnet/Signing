using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    public class Asn1BitString : Asn1Value
    {
        public ICollection<bool> Bits { get; }
        public string BitString { get; }

        public Asn1BitString(IEnumerable<bool> bits) : this(Asn1Class.Universal, Asn1Constants.Tags.BitString, bits) { }

        public Asn1BitString(Asn1Class @class, int tag, IEnumerable<bool> bits) : base(@class, tag)
        {
            Bits = bits.ToList();

            BitString = GenerateBitString();
        }

        private string GenerateBitString()
        {
            return string.Concat(Bits.Select(b => b ? "1" : "0"));
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1BitString other = obj as Asn1BitString;
            return other != null &&
                base.Equals(other) &&
                Bits.SequenceEqual(other.Bits);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Bits);
        }

        public override string ToString()
        {
            return base.ToString() + " BIT STRING " + BitString;
        }
    }
}