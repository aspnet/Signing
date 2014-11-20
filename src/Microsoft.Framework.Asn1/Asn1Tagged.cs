using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    /// <summary>
    /// Represents ASN.1 data that uses an implicit or explicit tag
    /// </summary>
    /// <remarks>
    /// Because the tag of the data has been changed, there is no
    /// way for the generic ASN.1 parser to interpret the data.
    /// Instead, it must be re-interpreted using data from the
    /// schema by calling the <see cref="BerParser.Reinterpret"/> method 
    /// and providing type information.
    /// </remarks>
    public abstract class Asn1Tagged : Asn1Value
    {
        public abstract bool IsPrimitive { get; }

        protected Asn1Tagged(Asn1Class @class, int tag) : base(@class, tag) { }
    }

    public class Asn1TaggedPrimitive : Asn1Tagged
    {
        public byte[] RawValue { get; }

        public override bool IsPrimitive
        {
            get
            {
                return true;
            }
        }

        // This type is only used when reading data. When writing data, the
        // client must know exactly what kind of tagged-primitive data is
        // to be written!
        public Asn1TaggedPrimitive(Asn1Class @class, int tag, byte[] rawValue)
            : base(@class, tag)
        {
            RawValue = rawValue;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1TaggedPrimitive other = obj as Asn1TaggedPrimitive;
            return other != null &&
                base.Equals(other) &&
                Enumerable.SequenceEqual(RawValue, other.RawValue);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(RawValue);
        }

        public override string ToString()
        {
            return base.ToString() + " UNKNOWN PRIMITIVE " + RawValue.Length + " bytes long";
        }
    }

    public class Asn1TaggedConstructed : Asn1Tagged
    {
        public IEnumerable<Asn1Value> Values { get; }

        public override bool IsPrimitive
        {
            get
            {
                return false;
            }
        }

        // This type is only used when reading data. When writing data, the
        // client must know exactly what kind of tagged-constructed data is
        // to be written!
        public Asn1TaggedConstructed(Asn1Class @class, int tag, IEnumerable<Asn1Value> values)
            : base(@class, tag)
        {
            Values = values;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1TaggedConstructed other = obj as Asn1TaggedConstructed;
            return other != null &&
                base.Equals(other) &&
                Enumerable.SequenceEqual(Values, other.Values);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Values);
        }

        public override string ToString()
        {
            return base.ToString() + " UNKNOWN CONSTRUCTED { " + String.Join(",", Values.Select(v => v.ToString())) + " }";
        }
    }
}