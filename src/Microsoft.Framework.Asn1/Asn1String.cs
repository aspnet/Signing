using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    public class Asn1String : Asn1Value
    {
        private static readonly Dictionary<Asn1StringType, Encoding> _encodings = new Dictionary<Asn1StringType, Encoding>() {
            { Asn1StringType.BmpString, Encoding.BigEndianUnicode },
            { Asn1StringType.UTF8String, Encoding.UTF8 },
            { Asn1StringType.PrintableString, Encoding.ASCII }
        };

        private static readonly Dictionary<Asn1StringType, int> _tags = new Dictionary<Asn1StringType, int>()
        {
            { Asn1StringType.BmpString, Asn1Constants.Tags.BmpString },
            { Asn1StringType.PrintableString, Asn1Constants.Tags.PrintableString },
            { Asn1StringType.UTF8String, Asn1Constants.Tags.UTF8String }
        };

        public string Value { get; }
        public Asn1StringType Type { get; }

        public Asn1String(string value, Asn1StringType type)
            : this(Asn1Class.Universal, GetTag(type), value, type)
        {
        }

        public Asn1String(Asn1Class @class, int tag, string value, Asn1StringType type)
            : base(@class, tag)
        {
            Value = value;
            Type = type;
        }

        public static Encoding GetEncoding(Asn1StringType type)
        {
            return _encodings[type];
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1String other = obj as Asn1String;
            return other != null &&
                base.Equals(other) &&
                Type == other.Type &&
                String.Equals(Value, other.Value, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Type).Add(Value);
        }

        public override string ToString()
        {
            return base.ToString() + "  " + Type.ToString().ToUpper() + " " + Value;
        }

        private static int GetTag(Asn1StringType type)
        {
            return _tags[type];
        }
    }

    public enum Asn1StringType
    {
        BmpString,
        UTF8String,
        PrintableString
    }
}