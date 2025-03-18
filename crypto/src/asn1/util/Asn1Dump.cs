using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.Utilities
{
    public static class Asn1Dump
    {
        private const string Tab = "    ";
        private const int SampleSize = 32;

        /**
         * dump a Der object as a formatted string with indentation
         *
         * @param obj the Asn1Object to be dumped out.
         */
        private static void AsString(string indent, bool verbose, Asn1Object obj, StringBuilder buf)
        {
            buf.Append(indent);

            if (obj is Asn1Null)
            {
                buf.AppendLine("NULL");
            }
            else if (obj is Asn1Sequence asn1Sequence)
            {
                if (asn1Sequence is BerSequence)
                {
                    buf.AppendLine("BER Sequence");
                }
                else if (!(asn1Sequence is DLSequence))
                {
                    buf.AppendLine("DER Sequence");
                }
                else
                {
                    buf.AppendLine("Sequence");
                }

                string elementsIndent = indent + Tab;

                for (int i = 0, count = asn1Sequence.Count; i < count; ++i)
                {
                    AsString(elementsIndent, verbose, asn1Sequence[i].ToAsn1Object(), buf);
                }
            }
            else if (obj is Asn1Set asn1Set)
            {
                if (asn1Set is BerSet)
                {
                    buf.AppendLine("BER Set");
                }
                else if (!(asn1Set is DLSet))
                {
                    buf.AppendLine("DER Set");
                }
                else
                {
                    buf.AppendLine("Set");
                }

                string elementsIndent = indent + Tab;

                for (int i = 0, count = asn1Set.Count; i < count; ++i)
                {
                    AsString(elementsIndent, verbose, asn1Set[i].ToAsn1Object(), buf);
                }
            }
            else if (obj is Asn1TaggedObject taggedObject)
            {
                if (taggedObject is BerTaggedObject)
                {
                    buf.Append("BER Tagged ");
                }
                else if (!(taggedObject is DLTaggedObject))
                {
                    buf.Append("DER Tagged ");
                }
                else
                {
                    buf.Append("Tagged ");
                }

                buf.Append(Asn1Utilities.GetTagText(taggedObject));

                if (!taggedObject.IsExplicit())
                {
                    buf.Append(" IMPLICIT");
                }

                buf.AppendLine();

                string baseIndent = indent + Tab;

                AsString(baseIndent, verbose, taggedObject.GetBaseObject().ToAsn1Object(), buf);
            }
            else if (obj is DerObjectIdentifier oid)
            {
                buf.AppendLine("ObjectIdentifier(" + oid.GetID() + ")");
            }
            else if (obj is Asn1RelativeOid relativeOid)
            {
                buf.AppendLine("RelativeOID(" + relativeOid.GetID() + ")");
            }
            else if (obj is DerBoolean derBoolean)
            {
                buf.AppendLine("Boolean(" + derBoolean.IsTrue + ")");
            }
            else if (obj is DerInteger derInteger)
            {
                buf.AppendLine("Integer(" + derInteger.Value + ")");
            }
            else if (obj is Asn1OctetString oct)
            {
                if (obj is BerOctetString)
                {
                    buf.Append("BER Octet String[");
                }
                else
                {
                    buf.Append("DER Octet String[");
                }

                buf.AppendLine(oct.GetOctetsLength() + "]");

                if (verbose)
                {
                    DumpBinaryDataAsString(buf, indent, oct.GetOctets());
                }
            }
            else if (obj is DerBitString bitString)
            {
                if (bitString is BerBitString)
                {
                    buf.Append("BER Bit String[");
                }
                else if (bitString is DLBitString)
                {
                    buf.Append("DL Bit String[");
                }
                else
                {
                    buf.Append("DER Bit String[");
                }

                buf.AppendLine(bitString.GetBytesLength() + ", " + bitString.PadBits + "]");

                if (verbose)
                {
                    DumpBinaryDataAsString(buf, indent, bitString.GetBytes());
                }
            }
            else if (obj is DerIA5String ia5String)
            {
                buf.AppendLine("IA5String(" + ia5String.GetString() + ")");
            }
            else if (obj is DerUtf8String utf8String)
            {
                buf.AppendLine("UTF8String(" + utf8String.GetString() + ")");
            }
            else if (obj is DerPrintableString printableString)
            {
                buf.AppendLine("PrintableString(" + printableString.GetString() + ")");
            }
            else if (obj is DerVisibleString visibleString)
            {
                buf.AppendLine("VisibleString(" + visibleString.GetString() + ")");
            }
            else if (obj is DerBmpString bmpString)
            {
                buf.AppendLine("BMPString(" + bmpString.GetString() + ")");
            }
            else if (obj is DerT61String t61String)
            {
                buf.AppendLine("T61String(" + t61String.GetString() + ")");
            }
            else if (obj is DerGraphicString graphicString)
            {
                buf.AppendLine("GraphicString(" + graphicString.GetString() + ")");
            }
            else if (obj is DerVideotexString videotexString)
            {
                buf.AppendLine("VideotexString(" + videotexString.GetString() + ")");
            }
            else if (obj is Asn1UtcTime utcTime)
            {
                buf.AppendLine("UTCTime(" + utcTime.TimeString + ")");
            }
            else if (obj is Asn1GeneralizedTime generalizedTime)
            {
                buf.AppendLine("GeneralizedTime(" + generalizedTime.TimeString + ")");
            }
            else if (obj is DerEnumerated en)
            {
                buf.AppendLine("DER Enumerated(" + en.Value + ")");
            }
            else if (obj is DerExternal ext)
            {
                buf.AppendLine("External ");
                string tab = indent + Tab;

                if (ext.DirectReference != null)
                {
                    buf.Append(tab);
                    buf.AppendLine("Direct Reference: " + ext.DirectReference.GetID());
                }
                if (ext.IndirectReference != null)
                {
                    buf.Append(tab);
                    buf.AppendLine("Indirect Reference: " + ext.IndirectReference.ToString());
                }
                if (ext.DataValueDescriptor != null)
                {
                    AsString(tab, verbose, ext.DataValueDescriptor, buf);
                }
                buf.Append(tab);
                buf.AppendLine("Encoding: " + ext.Encoding);
                AsString(tab, verbose, ext.ExternalContent, buf);
            }
            else
            {
                buf.Append(obj);
                buf.AppendLine();
            }
        }

        /// <summary>Parse ASN.1 objects from input <see cref="Stream"/>, and write them to the output.</summary>
        public static void Dump(Stream input, TextWriter output)
        {
            using (var asn1In = new Asn1InputStream(input, int.MaxValue, leaveOpen: true))
            {
                Asn1Object asn1Object;
                while ((asn1Object = asn1In.ReadObject()) != null)
                {
                    output.Write(DumpAsString(asn1Object));
                }
            }
        }

        /**
         * dump out a DER object as a formatted string, in non-verbose mode
         *
         * @param obj the Asn1Encodable to be dumped out.
         * @return  the resulting string.
         */
        public static string DumpAsString(Asn1Encodable obj)
        {
            return DumpAsString(obj, false);
        }

        /**
         * Dump out the object as a string
         *
         * @param obj the Asn1Encodable to be dumped out.
         * @param verbose  if true, dump out the contents of octet and bit strings.
         * @return  the resulting string.
         */
        public static string DumpAsString(Asn1Encodable obj, bool verbose)
        {
            StringBuilder buf = new StringBuilder();
            AsString("", verbose, obj.ToAsn1Object(), buf);
            return buf.ToString();
        }

        private static void DumpBinaryDataAsString(StringBuilder buf, string indent, byte[] bytes)
        {
            if (bytes.Length < 1)
                return;

            indent += Tab;

            for (int i = 0; i < bytes.Length; i += SampleSize)
            {
                int remaining = bytes.Length - i;
                int chunk = System.Math.Min(remaining, SampleSize);

                buf.Append(indent);
                buf.Append(Hex.ToHexString(bytes, i, chunk));
                for (int j = chunk; j < SampleSize; ++j)
                {
                    buf.Append("  ");
                }
                buf.Append(Tab);
                AppendAscString(buf, bytes, i, chunk);
                buf.AppendLine();
            }
        }

        private static void AppendAscString(StringBuilder buf, byte[] bytes, int off, int len)
        {
            for (int i = off; i != off + len; i++)
            {
                char c = (char)bytes[i]; 
                if (c >= ' ' && c <= '~')
                {
                    buf.Append(c);
                }
            }
        }
    }
}
