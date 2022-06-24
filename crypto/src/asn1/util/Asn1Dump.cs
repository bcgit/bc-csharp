using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.Utilities
{
    public sealed class Asn1Dump
    {
        private static readonly string NewLine = Platform.NewLine;

        private Asn1Dump()
        {
        }

        private const string Tab = "    ";
        private const int SampleSize = 32;

        /**
         * dump a Der object as a formatted string with indentation
         *
         * @param obj the Asn1Object to be dumped out.
         */
        private static void AsString(string indent, bool verbose, Asn1Object obj, StringBuilder buf)
        {
            if (obj is Asn1Null)
            {
                buf.Append(indent);
                buf.Append("NULL");
                buf.Append(NewLine);
            }
            else if (obj is Asn1Sequence)
            {
                buf.Append(indent);
                if (obj is BerSequence)
                {
                    buf.Append("BER Sequence");
                }
                else if (!(obj is DLSequence))
                {
                    buf.Append("DER Sequence");
                }
                else
                {
                    buf.Append("Sequence");
                }
                buf.Append(NewLine);

                Asn1Sequence sequence = (Asn1Sequence)obj;
                string elementsIndent = indent + Tab;

                for (int i = 0, count = sequence.Count; i < count; ++i)
                {
                    AsString(elementsIndent, verbose, sequence[i].ToAsn1Object(), buf);
                }
            }
            else if (obj is Asn1Set)
            {
                buf.Append(indent);
                if (obj is BerSet)
                {
                    buf.Append("BER Set");
                }
                else if (!(obj is DLSet))
                {
                    buf.Append("DER Set");
                }
                else
                {
                    buf.Append("Set");
                }
                buf.Append(NewLine);

                Asn1Set set = (Asn1Set)obj;
                string elementsIndent = indent + Tab;

                for (int i = 0, count = set.Count; i < count; ++i)
                {
                    AsString(elementsIndent, verbose, set[i].ToAsn1Object(), buf);
                }
            }
            else if (obj is Asn1TaggedObject)
            {
                buf.Append(indent);
                if (obj is BerTaggedObject)
                {
                    buf.Append("BER Tagged ");
                }
                else if (!(obj is DLTaggedObject))
                {
                    buf.Append("DER Tagged ");
                }
                else
                {
                    buf.Append("Tagged ");
                }

                Asn1TaggedObject o = (Asn1TaggedObject)obj;

                buf.Append(Asn1Utilities.GetTagText(o));

                if (!o.IsExplicit())
                {
                    buf.Append(" IMPLICIT ");
                }

                buf.Append(NewLine);

                string baseIndent = indent + Tab;

                AsString(baseIndent, verbose, o.GetBaseObject().ToAsn1Object(), buf);
            }
            else if (obj is DerObjectIdentifier)
            {
                buf.Append(indent + "ObjectIdentifier(" + ((DerObjectIdentifier)obj).Id + ")" + NewLine);
            }
            else if (obj is Asn1RelativeOid)
            {
                buf.Append(indent + "RelativeOID(" + ((Asn1RelativeOid)obj).Id + ")" + NewLine);
            }
            else if (obj is DerBoolean)
            {
                buf.Append(indent + "Boolean(" + ((DerBoolean)obj).IsTrue + ")" + NewLine);
            }
            else if (obj is DerInteger)
            {
                buf.Append(indent + "Integer(" + ((DerInteger)obj).Value + ")" + NewLine);
            }
            else if (obj is Asn1OctetString)
            {
                Asn1OctetString oct = (Asn1OctetString)obj;
                byte[] octets = oct.GetOctets();

                if (obj is BerOctetString)
                {
                    buf.Append(indent + "BER Octet String[" + octets.Length + "]" + NewLine);
                }
                else
                {
                    buf.Append(indent + "DER Octet String[" + octets.Length + "]" + NewLine);
                }

                if (verbose)
                {
                    buf.Append(DumpBinaryDataAsString(indent, octets));
                }
            }
            else if (obj is DerBitString)
            {
                DerBitString bitString = (DerBitString)obj;
                byte[] bytes = bitString.GetBytes();
                int padBits = bitString.PadBits;

                if (bitString is BerBitString)
                {
                    buf.Append(indent + "BER Bit String[" + bytes.Length + ", " + padBits + "]" + NewLine);
                }
                else if (bitString is DLBitString)
                {
                    buf.Append(indent + "DL Bit String[" + bytes.Length + ", " + padBits + "]" + NewLine);
                }
                else
                {
                    buf.Append(indent + "DER Bit String[" + bytes.Length + ", " + padBits + "]" + NewLine);
                }

                if (verbose)
                {
                    buf.Append(DumpBinaryDataAsString(indent, bytes));
                }
            }
            else if (obj is DerIA5String)
            {
                buf.Append(indent + "IA5String(" + ((DerIA5String)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerUtf8String)
            {
                buf.Append(indent + "UTF8String(" + ((DerUtf8String)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerPrintableString)
            {
                buf.Append(indent + "PrintableString(" + ((DerPrintableString)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerVisibleString)
            {
                buf.Append(indent + "VisibleString(" + ((DerVisibleString)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerBmpString)
            {
                buf.Append(indent + "BMPString(" + ((DerBmpString)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerT61String)
            {
                buf.Append(indent + "T61String(" + ((DerT61String)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerGraphicString)
            {
                buf.Append(indent + "GraphicString(" + ((DerGraphicString)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerVideotexString)
            {
                buf.Append(indent + "VideotexString(" + ((DerVideotexString)obj).GetString() + ")" + NewLine);
            }
            else if (obj is DerUtcTime)
            {
                buf.Append(indent + "UTCTime(" + ((DerUtcTime)obj).TimeString + ")" + NewLine);
            }
            else if (obj is DerGeneralizedTime)
            {
                buf.Append(indent + "GeneralizedTime(" + ((DerGeneralizedTime)obj).GetTime() + ")" + NewLine);
            }
            else if (obj is DerEnumerated)
            {
                DerEnumerated en = (DerEnumerated)obj;
                buf.Append(indent + "DER Enumerated(" + en.Value + ")" + NewLine);
            }
            else if (obj is DerExternal)
            {
                DerExternal ext = (DerExternal)obj;
                buf.Append(indent + "External " + NewLine);
                string tab = indent + Tab;

                if (ext.DirectReference != null)
                {
                    buf.Append(tab + "Direct Reference: " + ext.DirectReference.Id + NewLine);
                }
                if (ext.IndirectReference != null)
                {
                    buf.Append(tab + "Indirect Reference: " + ext.IndirectReference.ToString() + NewLine);
                }
                if (ext.DataValueDescriptor != null)
                {
                    AsString(tab, verbose, ext.DataValueDescriptor, buf);
                }
                buf.Append(tab + "Encoding: " + ext.Encoding + NewLine);
                AsString(tab, verbose, ext.ExternalContent, buf);
            }
            else
            {
                buf.Append(indent + obj.ToString() + NewLine);
            }
        }

        /// <summary>Parse ASN.1 objects from input <see cref="Stream"/>, and write them to the output.</summary>
        public static void Dump(Stream input, TextWriter output)
        {
            Asn1InputStream asn1InputStream = new Asn1InputStream(input);
            Asn1Object asn1Object;
            while ((asn1Object = asn1InputStream.ReadObject()) != null)
            {
                output.Write(DumpAsString(asn1Object));
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

        private static string DumpBinaryDataAsString(string indent, byte[] bytes)
        {
            if (bytes.Length < 1)
                return "";

            indent += Tab;

            StringBuilder buf = new StringBuilder();

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
                buf.Append(CalculateAscString(bytes, i, chunk));
                buf.Append(NewLine);
            }

            return buf.ToString();
        }

        private static string CalculateAscString(byte[] bytes, int off, int len)
        {
            StringBuilder buf = new StringBuilder();

            for (int i = off; i != off + len; i++)
            {
                char c = (char)bytes[i]; 
                if (c >= ' ' && c <= '~')
                {
                    buf.Append(c);
                }
            }

            return buf.ToString();
        }
    }
}
