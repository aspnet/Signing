using System;
using System.IO;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    public class PrettyPrintingAsn1Visitor : Asn1Visitor
    {
        private TextWriter _output;
        private bool _ansi;

        public int UnknownNodesEncountered { get; private set; }

        public PrettyPrintingAsn1Visitor(TextWriter output, bool ansi)
        {
            _output = output;
            _ansi = ansi;

            UnknownNodesEncountered = 0;
        }

        public override void Visit(Asn1Value value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            _output.WriteLine(line);
        }

        public override void Visit(Asn1SequenceBase value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append(value.IsSet ? "SET" : "SEQUENCE");
            _output.WriteLine(line);

            VisitSubValues(value.Values);
        }

        public override void Visit(Asn1Oid value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            string formatted = value.Oid;
            if (!string.IsNullOrEmpty(value.FriendlyName))
            {
                formatted += " (" + value.FriendlyName + ")";
            }

            line.Append("OID\t" + formatted);
            _output.WriteLine(line);
        }

        public override void Visit(Asn1Integer value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            line.Append("INTEGER\t" + value.Value.ToString());
            _output.WriteLine(line);
        }

        public override void Visit(Asn1BitString value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            line.Append("BIT STRING\t" + value.BitCount + " bits long");
            _output.WriteLine(line);
        }

        public override void Visit(Asn1Boolean value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            line.Append("BOOLEAN\t" + value.Value.ToString().ToUpperInvariant());
            _output.WriteLine(line);
        }

        public override void Visit(Asn1TaggedPrimitive value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            line.Append("UNKNOWN PRIMITIVE\t" + value.RawValue.Length.ToString() + " bytes long");
            _output.WriteLine(line);
        }

        public override void Visit(Asn1TaggedConstructed value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            line.Append("UNKNOWN CONSTRUCTED");
            _output.WriteLine(line);

            VisitSubValues(value.Values);
        }

        public override void Visit(Asn1Null value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append("NULL");
            _output.WriteLine(line);
        }

        public override void Visit(Asn1OctetString value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append("OCTET STRING\t" + value.Value.Length.ToString() + " bytes long");
            _output.WriteLine(line);
        }

        public override void Visit(Asn1UtcTime value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append("UTCTime\t" + value.Value.ToString("O"));
            _output.WriteLine(line);
        }

        public override void Visit(Asn1String value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append(value.Type.ToString() + "\t" + value.Value);
            _output.WriteLine(line);
        }

        public override void Visit(Asn1Unknown value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append("UNKNOWN!");
            _output.WriteLine(line);

            UnknownNodesEncountered++;
        }

        private void BuildCommonPrefix(Asn1Value value, StringBuilder line)
        {
            line.Append("  [" + Depth.ToString("00") + "]");
            line.Append(" (");

            // The longest possible string is 'ContextSpecific', 15 chars long
            line.Append(value.Class.ToString().PadLeft(15, ' ')); 

            line.Append(":");
            line.Append(value.Tag.ToString("00"));
            line.Append(") ");
            line.Append(" ");
            line.Append(new string(' ', (Depth + 1)));
        }
    }
}