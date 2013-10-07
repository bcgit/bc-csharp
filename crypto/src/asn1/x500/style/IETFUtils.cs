using System.Text;
using Org.BouncyCastle.Asn1.Crmf;
using System.IO;
using System;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System.Collections;
namespace Org.BouncyCastle.Asn1.X500.Style {


public class IETFUtils
{
    private static string unescape(string elt)
    {
        if (elt.Length == 0 || (elt.IndexOf('\\') < 0 && elt.IndexOf('"') < 0))
        {
            return elt.Trim();
        }

        char[] elts = elt.ToCharArray();
        bool escaped = false;
        bool quoted = false;
        StringBuilder buf = new StringBuilder(elt.Length);
        int start = 0;

        // if it's an escaped hash string and not an actual encoding in string form
        // we need to leave it escaped.
        if (elts[0] == '\\')
        {
            if (elts[1] == '#')
            {
                start = 2;
                buf.Append("\\#");
            }
        }

        bool nonWhiteSpaceEncountered = false;
        int     lastEscaped = 0;
        char    hex1 = (char)0;

        for (int i = start; i != elts.Length; i++)
        {
            char c = elts[i];

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
                }
                escaped = false;
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
                if (escaped && isHexDigit(c))
                {
                    if (hex1 != 0)
                    {
                        buf.Append((char)(convertHex(hex1) * 16 + convertHex(c)));
                        escaped = false;
                        hex1 = (char) 0;
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
            while (buf[buf.Length - 1] == ' ' && lastEscaped != (buf.Length - 1))
            {
                buf.Length = (buf.Length - 1);
            }
        }

        return buf.ToString();
    }

    private static bool isHexDigit(char c)
    {
        return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
    }

    private static int convertHex(char c)
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

    public static RDN[] rDNsFromString(string name, X500NameStyle x500Style)
    {
        X500NameTokenizer nTok = new X500NameTokenizer(name);
        X500NameBuilder builder = new X500NameBuilder(x500Style);

        while (nTok.hasMoreTokens())
        {
            string  token = nTok.nextToken();

            if (token.IndexOf('+') > 0)
            {
                X500NameTokenizer   pTok = new X500NameTokenizer(token, '+');
                X500NameTokenizer   vTok = new X500NameTokenizer(pTok.nextToken(), '=');

                string              attr = vTok.nextToken();

                if (!vTok.hasMoreTokens())
                {
                    throw new ArgumentException("badly formatted directory string");
                }

                string               value = vTok.nextToken();
                DerObjectIdentifier oid = x500Style.attrNameToOID(attr.Trim());

                if (pTok.hasMoreTokens())
                {
                    ArrayList oids = new ArrayList();
                    ArrayList values = new ArrayList();

                    oids.Add(oid);
                    values.Add(unescape(value));

                    while (pTok.hasMoreTokens())
                    {
                        vTok = new X500NameTokenizer(pTok.nextToken(), '=');

                        attr = vTok.nextToken();

                        if (!vTok.hasMoreTokens())
                        {
                            throw new ArgumentException("badly formatted directory string");
                        }

                        value = vTok.nextToken();
                        oid = x500Style.attrNameToOID(attr.Trim());


                        oids.Add(oid);
                        values.Add(unescape(value));
                    }

                    builder.addMultiValuedRDN(toOIDArray(oids), ToValueArray(values));
                }
                else
                {
                    builder.addRDN(oid, unescape(value));
                }
            }
            else
            {
                X500NameTokenizer   vTok = new X500NameTokenizer(token, '=');

                string              attr = vTok.nextToken();

                if (!vTok.hasMoreTokens())
                {
                    throw new ArgumentException("badly formatted directory string");
                }

                string               value = vTok.nextToken();
                DerObjectIdentifier oid = x500Style.attrNameToOID(attr.Trim());

                builder.addRDN(oid, unescape(value));
            }
        }

        return builder.build().getRDNs();
    }

    private static string[] ToValueArray(IList values)
    {
        string[] tmp = new string[values.Count];

        for (int i = 0; i != tmp.Length; i++)
        {
            tmp[i] = (string)values[i];
        }

        return tmp;
    }

    private static DerObjectIdentifier[] toOIDArray(IList oids)
    {
        DerObjectIdentifier[] tmp = new DerObjectIdentifier[oids.Count];

        for (int i = 0; i != tmp.Length; i++)
        {
            tmp[i] = (DerObjectIdentifier)oids[i];
        }

        return tmp;
    }

    public static string[] findAttrNamesForOID(
        DerObjectIdentifier oid,
        Hashtable            lookup)
    {
        int count = 0;
        foreach( var en in lookup.Values)
        {
            if (oid.Equals(en))
            {
                count++;
            }
        }

        string[] aliases = new string[count];
        count = 0;

        foreach(var en in lookup.Keys)
        {
            string key = (string)en;
            if (oid.Equals(lookup[key]))
            {
                aliases[count++] = key;
            }
        }

        return aliases;
    }

    public static DerObjectIdentifier decodeAttrName(
        string      name,
        Hashtable   lookUp)
    {
        if (name.ToUpper().StartsWith("OID."))
        {
            return new DerObjectIdentifier(name.Substring(4));
        }
        else if (name[0] >= '0' && name[0] <= '9')
        {
            return new DerObjectIdentifier(name);
        }

        DerObjectIdentifier oid = (DerObjectIdentifier)lookUp[name.ToLower()];
        if (oid == null)
        {
            throw new ArgumentException("Unknown object id - " + name + " - passed to distinguished name");
        }

        return oid;
    }

    public static Asn1Encodable valueFromHexString(
        string  str,
        int     off)
    {
        byte[] data = new byte[(str.Length - off) / 2];
        for (int index = 0; index != data.Length; index++)
        {
            char left = str[(index * 2) + off];
            char right = str[(index * 2) + off + 1];

            data[index] = (byte)((convertHex(left) << 4) | convertHex(right));
        }

        return Asn1Object.FromByteArray(data);
    }

    public static void appendRDN(
        StringBuilder          buf,
        RDN                   rdn,
        Hashtable             oidSymbols)
    {
        if (rdn.isMultiValued())
        {
            AttributeTypeAndValue[] atv = rdn.GetTypesAndValues();
            bool firstAtv = true;

            for (int j = 0; j != atv.Length; j++)
            {
                if (firstAtv)
                {
                    firstAtv = false;
                }
                else
                {
                    buf.Append('+');
                }

                IETFUtils.appendTypeAndValue(buf, atv[j], oidSymbols);
            }
        }
        else
        {
            IETFUtils.appendTypeAndValue(buf, rdn.GetFirst(), oidSymbols);
        }
    }

    public static void appendTypeAndValue(
        StringBuilder          buf,
        AttributeTypeAndValue typeAndValue,
        Hashtable             oidSymbols)
    {
        string  sym = (string)oidSymbols[typeAndValue.Type];

        if (sym != null)
        {
            buf.Append(sym);
        }
        else
        {
            buf.Append(typeAndValue.Type.Id);
        }

        buf.Append('=');

        buf.Append(valueToString(typeAndValue.Value));
    }

    public static string valueToString(Asn1Encodable value)
    {
        StringBuilder vBuf = new StringBuilder();

        if (value is IAsn1String && !(value is DerUniversalString))
        {
            string v = ((IAsn1String)value).GetString();
            if (v.Length > 0 && v[0] == '#')
            {
                vBuf.Append("\\" + v);
            }
            else
            {
                vBuf.Append(v);
            }
        }
        else
        {
            try
            {
                vBuf.Append("#" + bytesToString(Hex.Encode(value.ToAsn1Object().GetDerEncoded())));
            }
            catch (IOException e)
            {
                throw new ArgumentException("Other value has no encoded form");
            }
        }

        int     end = vBuf.Length;
        int     index = 0;

        if (vBuf.Length >= 2 && vBuf[0] == '\\' && vBuf[1] == '#')
        {
            index += 2;
        }

        while (index != end)
        {
            if ((vBuf[index] == ',')
               || (vBuf[index] == '"')
               || (vBuf[index] == '\\')
               || (vBuf[index] == '+')
               || (vBuf[index] == '=')
               || (vBuf[index] == '<')
               || (vBuf[index] == '>')
               || (vBuf[index] == ';'))
            {
                vBuf.Insert(index, "\\");
                index++;
                end++;
            }

            index++;
        }

        int start = 0;
        if (vBuf.Length > 0)
        {
            while (vBuf[start] == ' ')
            {
                vBuf.Insert(start, "\\");
                start += 2;
            }
        }

        int endBuf = vBuf.Length - 1;

        while (endBuf >= 0 && vBuf[endBuf] == ' ')
        {
            vBuf.Insert(endBuf, '\\');
            endBuf--;
        }

        return vBuf.ToString();
    }

    private static string bytesToString(
        byte[] data)
    {
        char[]  cs = new char[data.Length];

        for (int i = 0; i != cs.Length; i++)
        {
            cs[i] = (char)(data[i] & 0xff);
        }

        return new string(cs);
    }

    public static string canonicalize(string s)
    {
        string value = s.ToLower().Trim();

        if (value.Length > 0 && value[0] == '#')
        {
            var obj = decodeObject(value);

            if (obj is IAsn1String)
            {
                value = ((IAsn1String)obj).GetString().Trim().ToLower();
            }
        }

        value = stripInternalSpaces(value);

        return value;
    }

    private static Asn1Object decodeObject(string oValue)
    {
        try
        {
            return Asn1Object.FromByteArray(Hex.Decode(oValue.Substring(1)));
        }
        catch (IOException e)
        {
            throw new InvalidOperationException("Unknown encoding.", e);
        }
    }

    public static string stripInternalSpaces(
        string str)
    {
        StringBuilder res = new StringBuilder();

        if (str.Length != 0)
        {
            char c1 = str[0];

            res.Append(c1);

            for (int k = 1; k < str.Length; k++)
            {
                char c2 = str[k];
                if (!(c1 == ' ' && c2 == ' '))
                {
                    res.Append(c2);
                }
                c1 = c2;
            }
        }

        return res.ToString();
    }

    public static bool rDNAreEqual(RDN rdn1, RDN rdn2)
    {
        if (rdn1.isMultiValued())
        {
            if (rdn2.isMultiValued())
            {
                AttributeTypeAndValue[] atvs1 = rdn1.GetTypesAndValues();
                AttributeTypeAndValue[] atvs2 = rdn2.GetTypesAndValues();

                if (atvs1.Length != atvs2.Length)
                {
                    return false;
                }

                for (int i = 0; i != atvs1.Length; i++)
                {
                    if (!atvAreEqual(atvs1[i], atvs2[i]))
                    {
                        return false;
                    }
                }
            }
            else
            {
                return false;
            }
        }
        else
        {
            if (!rdn2.isMultiValued())
            {
                return atvAreEqual(rdn1.GetFirst(), rdn2.GetFirst());
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    private static bool atvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2)
    {
        if (atv1 == atv2)
        {
            return true;
        }

        if (atv1 == null)
        {
            return false;
        }

        if (atv2 == null)
        {
            return false;
        }

        DerObjectIdentifier o1 = atv1.Type;
        DerObjectIdentifier o2 = atv2.Type;

        if (!o1.Equals(o2))
        {
            return false;
        }

        string v1 = IETFUtils.canonicalize(IETFUtils.valueToString(atv1.Value));
        string v2 = IETFUtils.canonicalize(IETFUtils.valueToString(atv2.Value));

        if (!v1.Equals(v2))
        {
            return false;
        }

        return true;
    }
}
}