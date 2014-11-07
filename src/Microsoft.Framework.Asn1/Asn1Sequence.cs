using System;
using System.Collections.Generic;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Sequence : Asn1Value
    {
        public IEnumerable<Asn1Value> Values { get; }

        public Asn1Sequence(Asn1Class @class, int tag, int length, Asn1Encoding encoding, IEnumerable<Asn1Value> values)
            : base(@class, tag, length, encoding)
        {
            Values = values;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}