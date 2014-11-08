using System;

namespace Microsoft.Framework.Asn1
{
    public abstract class Asn1Value
    {
        public Asn1Class Class { get; }
        public int Tag { get; }
        
        protected Asn1Value(Asn1Class @class, int tag)
        {
            Class = @class;
            Tag = tag;
        }

        public virtual void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}