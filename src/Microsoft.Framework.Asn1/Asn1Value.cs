using System;

namespace Microsoft.Framework.Asn1
{
    public abstract class Asn1Value
    {
        public Asn1Class Class { get; }
        public int Tag { get; }
        public int Length { get; }
        public Asn1Encoding Encoding { get; }

        protected Asn1Value(Asn1Class @class, int tag, int length, Asn1Encoding encoding)
        {
            Class = @class;
            Tag = tag;
            Length = length;
            Encoding = encoding;
        }

        public virtual void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}