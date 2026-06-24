using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.X500.Style
{
    // TODO[api] Make static
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
            // Accumulator for a run of consecutive \HH escapes. Per RFC 4514 sec. 2.4
            // a \HH escape produces a single octet, and the resulting octet sequence
            // is the UTF-8 encoding of the character — so a run of pairs must be
            // decoded as UTF-8 (RFC 5280 sec. 4.1.2.4), not one Java char per pair.
            MemoryStream hexBytes = new MemoryStream(capacity: 8);
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
            int lastEscaped = -1;
            int hex1 = -1;

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
                        CheckCompleteHexPair(hex1);
                        FlushHexBytes(buf, hexBytes, ref lastEscaped);
                        buf.Append(c);
                        escaped = false;
                    }
                }
                else if (c == '\\' && !(escaped || quoted))
                {
                    escaped = true;
                    // In case hexBytes is not empty, lastEscaped will get updated when hexBytes is flushed
                    lastEscaped = buf.Length;
                }
                else if (c == ' ' && !escaped && !nonWhiteSpaceEncountered)
                {
                    // Skip leading spaces
                }
                else if (escaped && IsHexDigit(c))
                {
                    int hexDigit = ConvertHex(c);
                    if (hex1 < 0)
                    {
                        hex1 = hexDigit;
                    }
                    else
                    {
                        hexBytes.WriteByte((byte)(hex1 * 16 + hexDigit));
                        escaped = false;
                        hex1 = -1;
                    }
                }
                else
                {
                    // A '\' followed by a single hex digit and then a non-hex char is an
                    // incomplete hexpair (RFC 4514 sec. 2.4 requires two), not a literal.
                    CheckCompleteHexPair(hex1);
                    FlushHexBytes(buf, hexBytes, ref lastEscaped);
                    buf.Append(c);
                    escaped = false;
                }
            }

            // A '\' followed by a single hex digit at end of input is likewise incomplete.
            CheckCompleteHexPair(hex1);
            FlushHexBytes(buf, hexBytes, ref lastEscaped);

            if (buf.Length > 0)
            {
                while (buf[buf.Length - 1] == ' ' && lastEscaped < buf.Length - 1)
                {
                    buf.Length = buf.Length - 1;
                }
            }

            return buf.ToString();
        }

        private static void FlushHexBytes(StringBuilder buf, MemoryStream hexBytes, ref int lastEscaped)
        {
            int length = Convert.ToInt32(hexBytes.Position);
            if (length > 0)
            {
                string decoded = Strings.FromUtf8ByteArray(hexBytes.ToArray());
                hexBytes.Position = 0L;
                buf.Append(decoded);
                lastEscaped = buf.Length - 1;
            }
        }

        private static void CheckCompleteHexPair(int hex1)
        {
            if (hex1 >= 0)
                throw new ArgumentException("invalid hex escape in directory string");
        }

        private static bool IsHexDigit(char c)
        {
            return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
        }

        private static int ConvertHex(char c)
        {
            if ('0' <= c && c <= '9')
                return c - '0';

            if ('a' <= c && c <= 'f')
                return c - 'a' + 10;

            return c - 'A' + 10;
        }

        public static void AppendTypeAndValue(StringBuilder buf, AttributeTypeAndValue typeAndValue,
            IDictionary<DerObjectIdentifier, string> oidSymbols)
        {
            AppendTypeAndValue(buf, typeAndValue.Type, typeAndValue.Value, oidSymbols);
        }

        internal static void AppendTypeAndValue(StringBuilder buf, DerObjectIdentifier attrType,
            Asn1Encodable attrValue, IDictionary<DerObjectIdentifier, string> oidSymbols)
        {
            if (oidSymbols.TryGetValue(attrType, out var sym))
            {
                buf.Append(sym);
            }
            else
            {
                buf.Append(attrType.GetID());
            }

            buf.Append('=');

            AppendValue(buf, attrValue);
        }

        private static void AppendValue(StringBuilder buf, Asn1Encodable value)
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

            // Escape in a single linear pass into a fresh builder. The previous implementation escaped by
            // inserting a backslash into the buffer it was scanning (O(n) per insert), so a value of n
            // RFC 4514 special characters - or n leading/trailing spaces - cost ~n^2/2 character moves: a
            // CPU-exhaustion vector for an attacker-supplied large RDN. Output is unchanged.

            int len = vBuf.Length;

            // A leading "\#" (produced above when the value begins with '#') is emitted verbatim and the
            // leading-space escaping is suppressed, matching the original phase ordering.
            bool hashPrefix = len >= 2 && vBuf[0] == '\\' && vBuf[1] == '#';

            int firstNonSpace = 0;
            while (firstNonSpace < len && vBuf[firstNonSpace] == ' ')
            {
                firstNonSpace++;
            }
            int lastNonSpace;
            if (firstNonSpace < len)
            {
                lastNonSpace = len;
                while (vBuf[--lastNonSpace] == ' ')
                {
                }
            }
            else
            {
                lastNonSpace = -1;
            }

            int index = 0;
            if (hashPrefix)
            {
                buf.Append("\\#");
                index = 2;
            }

            for (; index < len; index++)
            {
                char c = vBuf[index];
                bool escape;
                switch (c)
                {
                case ',':
                case '"':
                case '\\':
                case '+':
                case '=':
                case '<':
                case '>':
                case ';':
                    escape = true;
                    break;
                case ' ':
                    // leading spaces escaped only without a "\#" prefix; trailing spaces always escaped.
                    escape = (!hashPrefix && index < firstNonSpace) || index > lastNonSpace;
                    break;
                default:
                    escape = false;
                    break;
                }
                if (escape)
                {
                    buf.Append('\\');
                }
                buf.Append(c);
            }
        }

        public static string ValueToString(Asn1Encodable value)
        {
            StringBuilder buf = new StringBuilder(64);
            AppendValue(buf, value);
            return buf.ToString();
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
                throw new InvalidOperationException("unknown encoding in name", e);
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
