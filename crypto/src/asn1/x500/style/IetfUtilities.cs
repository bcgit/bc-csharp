using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.X500.Style
{
    // TODO[api] static
    public abstract class IetfUtilities
    {
        internal static string Unescape(string elt)
        {
            if (elt.Length < 1)
                return elt;

            if (elt.IndexOf('\\') < 0 && elt.IndexOf('"') < 0)
                return elt.Trim();

            bool escaped = false;
            bool quoted = false;
            StringBuilder buf = new StringBuilder(elt.Length);
            int start = 0;

            // if it's an escaped hash string and not an actual encoding in string form
            // we need to leave it escaped.
            if (elt[0] == '\\')
            {
                if (elt[1] == '#')
                {
                    start = 2;
                    buf.Append("\\#");
                }
            }

            bool nonWhiteSpaceEncountered = false;
            int lastEscaped = 0;
            char hex1 = Convert.ToChar(0);

            for (int i = start; i != elt.Length; i++)
            {
                char c = elt[i];

                if (c != ' ')
                {
                    nonWhiteSpaceEncountered = true;
                }

                if (c == '"')
                {
                    if (!escaped)
                    {
                        quoted = !quoted;
                    }
                    else
                    {
                        buf.Append(c);
                        escaped = false;
                    }
                }
                else if (c == '\\' && !(escaped || quoted))
                {
                    escaped = true;
                    lastEscaped = buf.Length;
                }
                else
                {
                    if (c == ' ' && !escaped && !nonWhiteSpaceEncountered)
                    {
                        continue;
                    }
                    if (escaped && IsHexDigit(c))
                    {
                        if (hex1 != 0)
                        {
                            buf.Append(Convert.ToChar(ConvertHex(hex1) * 16 + ConvertHex(c)));
                            escaped = false;
                            hex1 = Convert.ToChar(0);
                            continue;
                        }
                        hex1 = c;
                        continue;
                    }
                    buf.Append(c);
                    escaped = false;
                }
            }

            if (buf.Length > 0)
            {
                int last = buf.Length - 1;
                while (buf[last] == ' ' && lastEscaped != last)
                {
                    buf.Length = last;
                }
            }

            return buf.ToString();
        }

        private static bool IsHexDigit(char c)
        {
            return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
        }

        private static int ConvertHex(char c)
        {
            if ('0' <= c && c <= '9')
            {
                return c - '0';
            }
            if ('a' <= c && c <= 'f')
            {
                return c - 'a' + 10;
            }
            return c - 'A' + 10;
        }

        public static string ValueToString(Asn1Encodable value)
        {
            StringBuilder vBuf = new StringBuilder();

            if (value is IAsn1String str && !(value is DerUniversalString))
            {
                string v = str.GetString();
                if (v.Length > 0 && v[0] == '#')
                {
                    vBuf.Append('\\');
                }

                vBuf.Append(v);
            }
            else
            {
                try
                {
                    vBuf.Append('#');
                    vBuf.Append(Hex.ToHexString(value.ToAsn1Object().GetEncoded(Asn1Encodable.Der)));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("Other value has no encoded form", e);
                }
            }

            int end = vBuf.Length;
            int index = 0;

            if (vBuf.Length >= 2 && vBuf[0] == '\\' && vBuf[1] == '#')
            {
                index += 2;
            }

            while (index != end)
            {
                switch (vBuf[index])
                {
                    case ',':
                    case '"':
                    case '\\':
                    case '+':
                    case '=':
                    case '<':
                    case '>':
                    case ';':
                    {
                        vBuf.Insert(index, "\\");
                        index += 2;
                        ++end;
                        break;
                    }
                    default:
                    {
                        ++index;
                        break;
                    }
                }
            }

            int start = 0;
            if (vBuf.Length > 0)
            {
                while (vBuf.Length > start && vBuf[start] == ' ')
                {
                    vBuf.Insert(start, "\\");
                    start += 2;
                }
            }

            int endBuf = vBuf.Length - 1;

            while (endBuf >= 0 && vBuf[endBuf] == ' ')
            {
                vBuf.Insert(endBuf, "\\");
                endBuf--;
            }

            return vBuf.ToString();
        }

        public static string Canonicalize(string s)
        {
            string value = s.ToLowerInvariant();

            if (value.Length > 0 && value[0] == '#')
            {
                Asn1Object obj = DecodeObject(value);

                if (obj is IAsn1String str)
                {
                    value = str.GetString().ToLowerInvariant();
                }
            }

            if (value.Length > 1)
            {
                int start = 0;
                while (start + 1 < value.Length && value[start] == '\\' && value[start + 1] == ' ')
                {
                    start += 2;
                }

                int end = value.Length - 1;
                while (end - 1 > 0 && value[end - 1] == '\\' && value[end] == ' ')
                {
                    end -= 2;
                }

                if (start > 0 || end < value.Length - 1)
                {
                    value = value.Substring(start, end + 1 - start);
                }
            }

            return StripInternalSpaces(value);
        }

        public static string CanonicalString(Asn1Encodable value)
        {
            return Canonicalize(ValueToString(value));
        }

        private static Asn1Object DecodeObject(string oValue)
        {
            try
            {
                return Asn1Object.FromByteArray(Hex.DecodeStrict(oValue, 1, oValue.Length - 1));
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("unknown encoding in name: " + e);
            }
        }

        public static string StripInternalSpaces(string str)
        {
            if (str.IndexOf("  ") < 0)
                return str;

            StringBuilder res = new StringBuilder();

            char c1 = str[0];
            res.Append(c1);

            for (int k = 1; k < str.Length; k++)
            {
                char c2 = str[k];
                if (!(' ' == c1 && ' ' == c2))
                {
                    res.Append(c2);
                    c1 = c2;
                }
            }

            return res.ToString();
        }

        public static bool RdnAreEqual(Rdn rdn1, Rdn rdn2)
        {
            if (rdn1.Count != rdn2.Count)
                return false;

            AttributeTypeAndValue[] atvs1 = rdn1.GetTypesAndValues();
            AttributeTypeAndValue[] atvs2 = rdn2.GetTypesAndValues();

            if (atvs1.Length != atvs2.Length)
                return false;

            for (int i = 0; i != atvs1.Length; i++)
            {
                if (!AtvAreEqual(atvs1[i], atvs2[i]))
                    return false;
            }

            return true;
        }

        private static bool AtvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2)
        {
            if (atv1 == atv2)
                return true;
            if (null == atv1 || null == atv2)
                return false;

            DerObjectIdentifier o1 = atv1.Type;
            DerObjectIdentifier o2 = atv2.Type;

            if (!o1.Equals(o2))
                return false;

            string v1 = CanonicalString(atv1.Value);
            string v2 = CanonicalString(atv2.Value);

            if (!v1.Equals(v2))
                return false;

            return true;
        }
    }
}
