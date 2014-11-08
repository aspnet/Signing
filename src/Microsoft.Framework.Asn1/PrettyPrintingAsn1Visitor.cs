using System;
using System.IO;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    public class PrettyPrintingAsn1Visitor : Asn1Visitor
    {
        private TextWriter _output;
        private bool _ansi;

        private int _depth = 0;

        public PrettyPrintingAsn1Visitor(TextWriter output, bool ansi)
        {
            _output = output;
            _ansi = ansi;
        }

        public override void Visit(Asn1Value value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            _output.WriteLine(line);
        }

        public override void Visit(Asn1Sequence value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append(" SEQUENCE");
            _output.WriteLine(line);

            _depth++;
            foreach (var subvalue in value.Values)
            {
                subvalue.Accept(this);
            }
            _depth--;
        }

        public override void Visit(Asn1Oid value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append(" OID\t" + value.Oid);
            _output.WriteLine(line);
        }

        public override void Visit(Asn1ExplicitTag value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append(" TAGGED");
            _output.WriteLine(line);
            value.Value.Accept(this);
        }

        public override void Visit(Asn1Unknown value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append(" UNKNOWN!");
            _output.WriteLine(line);
        }

        private void BuildCommonPrefix(Asn1Value value, StringBuilder line)
        {
            line.Append("  [" + _depth + "]");
            line.Append(" (");
            line.Append(value.Class.ToString().PadLeft(15, ' '));
            line.Append(":");
            line.Append(value.Tag.ToString("00"));
            line.Append(") ");
            line.Append(" ");
            line.Append(new string(' ', _depth + 1));
        }
    }
}