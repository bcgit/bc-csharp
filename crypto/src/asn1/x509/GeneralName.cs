using System;
using System.Globalization;
using System.Text;

using Org.BouncyCastle.Utilities;

using NetUtils = Org.BouncyCastle.Utilities.Net;

namespace Org.BouncyCastle.Asn1.X509
{
	/**
     * The GeneralName object.
     * <pre>
     * GeneralName ::= CHOICE {
     *      otherName                       [0]     OtherName,
     *      rfc822Name                      [1]     IA5String,
     *      dNSName                         [2]     IA5String,
     *      x400Address                     [3]     ORAddress,
     *      directoryName                   [4]     Name,
     *      ediPartyName                    [5]     EDIPartyName,
     *      uniformResourceIdentifier       [6]     IA5String,
     *      iPAddress                       [7]     OCTET STRING,
     *      registeredID                    [8]     OBJECT IDENTIFIER}
     *
     * OtherName ::= Sequence {
     *      type-id    OBJECT IDENTIFIER,
     *      value      [0] EXPLICIT ANY DEFINED BY type-id }
     *
     * EDIPartyName ::= Sequence {
     *      nameAssigner            [0]     DirectoryString OPTIONAL,
     *      partyName               [1]     DirectoryString }
     * </pre>
     */
	public class GeneralName
        : Asn1Encodable, IAsn1Choice
    {
        public const int OtherName					= 0;
        public const int Rfc822Name					= 1;
        public const int DnsName					= 2;
        public const int X400Address				= 3;
        public const int DirectoryName				= 4;
        public const int EdiPartyName				= 5;
        public const int UniformResourceIdentifier	= 6;
        public const int IPAddress					= 7;
        public const int RegisteredID				= 8;

        public static GeneralName GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

		public static GeneralName GetInstance(Asn1TaggedObject tagObj, bool explicitly) =>
            Asn1Utilities.GetInstanceChoice(tagObj, explicitly, GetInstance);

        public static GeneralName GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is GeneralName generalName)
                return generalName;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new GeneralName(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        public static GeneralName GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case EdiPartyName:
                    // TODO[api] Actually return EdiPartyName instead of only using it for validation
                    //return Asn1.X509.EdiPartyName.GetTagged(taggedObject, false);
                    var seq = Asn1Sequence.GetTagged(taggedObject, false);
                    Asn1.X509.EdiPartyName.GetInstance(seq);
                    return seq;

                case OtherName:
                case X400Address:
                    return Asn1Sequence.GetTagged(taggedObject, false);

                case DnsName:
                case Rfc822Name:
                case UniformResourceIdentifier:
                    return DerIA5String.GetTagged(taggedObject, false);

                case DirectoryName:
                    // CHOICE so explicit
                    return X509Name.GetTagged(taggedObject, true);

                case IPAddress:
                    return Asn1OctetString.GetTagged(taggedObject, false);

                case RegisteredID:
                    return DerObjectIdentifier.GetTagged(taggedObject, false);
                }
            }
            return null;
        }

        private readonly int m_tag;
        private readonly Asn1Encodable m_object;

		public GeneralName(X509Name directoryName)
        {
			m_tag = DirectoryName;
            m_object = directoryName;
        }

		/**
         * When the subjectAltName extension contains an Internet mail address,
         * the address MUST be included as an rfc822Name. The format of an
         * rfc822Name is an "addr-spec" as defined in RFC 822 [RFC 822].
         *
         * When the subjectAltName extension contains a domain name service
         * label, the domain name MUST be stored in the dNSName (an IA5String).
         * The name MUST be in the "preferred name syntax," as specified by RFC
         * 1034 [RFC 1034].
         *
         * When the subjectAltName extension contains a URI, the name MUST be
         * stored in the uniformResourceIdentifier (an IA5String). The name MUST
         * be a non-relative URL, and MUST follow the URL syntax and encoding
         * rules specified in [RFC 1738].  The name must include both a scheme
         * (e.g., "http" or "ftp") and a scheme-specific-part.  The scheme-
         * specific-part must include a fully qualified domain name or IP
         * address as the host.
         *
         * When the subjectAltName extension contains a iPAddress, the address
         * MUST be stored in the octet string in "network byte order," as
         * specified in RFC 791 [RFC 791]. The least significant bit (LSB) of
         * each octet is the LSB of the corresponding byte in the network
         * address. For IP Version 4, as specified in RFC 791, the octet string
         * MUST contain exactly four octets.  For IP Version 6, as specified in
         * RFC 1883, the octet string MUST contain exactly sixteen octets [RFC
         * 1883].
         */
        public GeneralName(Asn1Object name, int tag)
        {
            m_tag = tag;
            m_object = name;
        }

		public GeneralName(int tag, Asn1Encodable name)
        {
            m_tag = tag;
            m_object = name;
        }

        /**
		 * Create a GeneralName for the given tag from the passed in string.
		 * <p>
		 * This constructor can handle:
		 * <ul>
		 * <li>rfc822Name</li>
		 * <li>iPAddress</li>
		 * <li>directoryName</li>
		 * <li>dNSName</li>
		 * <li>uniformResourceIdentifier</li>
		 * <li>registeredID</li>
		 * </ul>
		 * For x400Address, otherName and ediPartyName there is no common string
		 * format defined.
		 * </p><p>
		 * Note: A directory name can be encoded in different ways into a byte
		 * representation. Be aware of this if the byte representation is used for
		 * comparing results.
		 * </p>
		 *
		 * @param tag tag number
		 * @param name string representation of name
		 * @throws ArgumentException if the string encoding is not correct or
		 *             not supported.
		 */
        public GeneralName(int tag, string name)
        {
            m_tag = tag;

            switch (tag)
            {
            case DnsName:
            case Rfc822Name:
            case UniformResourceIdentifier:
                m_object = new DerIA5String(name);
                break;

            case DirectoryName:
                m_object = new X509Name(name);
                break;

            case IPAddress:
            {
                byte[] encoding = ToGeneralNameEncoding(name)
                    ?? throw new ArgumentException("IP Address is invalid", nameof(name));

                m_object = new DerOctetString(encoding);
                break;
            }

            case RegisteredID:
                m_object = new DerObjectIdentifier(name);
                break;

            case EdiPartyName:
            case OtherName:
            case X400Address:
            default:
            {
                string message = string.Format("can't process string for tag: {0}",
                    Asn1Utilities.GetTagText(Asn1Tags.ContextSpecific, tag));

                throw new ArgumentException(message, nameof(tag));
            }
            }
        }

        public int TagNo => m_tag;

		public Asn1Encodable Name => m_object;

        public override Asn1Object ToAsn1Object()
        {
            // directoryName is explicitly tagged as it is a CHOICE
            bool isExplicit = (m_tag == DirectoryName);

            return new DerTaggedObject(isExplicit, m_tag, m_object);
        }

        public override string ToString()
		{
			StringBuilder buf = new StringBuilder();
			buf.Append(m_tag);
			buf.Append(": ");

			switch (m_tag)
			{
			case Rfc822Name:
			case DnsName:
			case UniformResourceIdentifier:
				buf.Append(DerIA5String.GetInstance(m_object).GetString());
				break;
			case DirectoryName:
				buf.Append(X509Name.GetInstance(m_object).ToString());
				break;
			default:
				buf.Append(m_object.ToString());
				break;
			}

			return buf.ToString();
		}

		private byte[] ToGeneralNameEncoding(string ip)
		{
			if (NetUtils.IPAddress.IsValidIPv6WithNetmask(ip) || NetUtils.IPAddress.IsValidIPv6(ip))
			{
				int slashIndex = Platform.IndexOf(ip, '/');

				if (slashIndex < 0)
				{
					byte[] addr = new byte[16];
					int[] parsedIp = ParseIPv6(ip);
					CopyInts(parsedIp, addr, 0);

					return addr;
				}
				else
				{
					byte[] addr = new byte[32];
					int[] parsedIp = ParseIPv6(ip.Substring(0, slashIndex));
					CopyInts(parsedIp, addr, 0);
					string mask = ip.Substring(slashIndex + 1);
					if (Platform.IndexOf(mask, ':') > 0)
					{
						parsedIp = ParseIPv6(mask);
					}
					else
					{
						parsedIp = ParseIPv6Mask(mask);
					}
					CopyInts(parsedIp, addr, 16);

					return addr;
				}
			}
			else if (NetUtils.IPAddress.IsValidIPv4WithNetmask(ip) || NetUtils.IPAddress.IsValidIPv4(ip))
			{
				int slashIndex = Platform.IndexOf(ip, '/');

				if (slashIndex < 0)
				{
					byte[] addr = new byte[4];

					ParseIPv4(ip, addr, 0);

					return addr;
				}
				else
				{
					byte[] addr = new byte[8];

					ParseIPv4(ip.Substring(0, slashIndex), addr, 0);

					string mask = ip.Substring(slashIndex + 1);
					if (Platform.IndexOf(mask, '.') > 0)
					{
						ParseIPv4(mask, addr, 4);
					}
					else
					{
						ParseIPv4Mask(mask, addr, 4);
					}

					return addr;
				}
			}

			return null;
		}

        private static void CopyInts(int[] parsedIp, byte[] addr, int offSet)
        {
            for (int i = 0; i != parsedIp.Length; i++)
            {
                addr[(i * 2) + offSet] = (byte)(parsedIp[i] >> 8);
                addr[(i * 2 + 1) + offSet] = (byte)parsedIp[i];
            }
        }

        private static void ParseIPv4(string ip, byte[] addr, int offset)
        {
            foreach (string token in ip.Split('.', '/'))
            {
                addr[offset++] = (byte)int.Parse(token);
            }
        }

        private static void ParseIPv4Mask(string mask, byte[] addr, int offset)
		{
            int bits = int.Parse(mask);
            while (bits >= 8)
            {
                addr[offset++] = byte.MaxValue;
                bits -= 8;
            }
            if (bits > 0)
            {
                addr[offset] = (byte)(0xFF00 >> bits);
            }
        }

        private static int[] ParseIPv6(string ip)
		{
			if (Platform.StartsWith(ip, "::"))
			{
				ip = ip.Substring(1);
			}
			else if (Platform.EndsWith(ip, "::"))
			{
				ip = ip.Substring(0, ip.Length - 1);
			}

			int index = 0;
			int[] val = new int[8];

			int doubleColon = -1;

			foreach (var e in ip.Split(':'))
			{
				if (e.Length == 0)
				{
					doubleColon = index;
					val[index++] = 0;
				}
				else
				{
					if (Platform.IndexOf(e, '.') < 0)
					{
						val[index++] = int.Parse(e, NumberStyles.AllowHexSpecifier);
					}
					else
					{
						string[] tokens = e.Split('.');

						val[index++] = (int.Parse(tokens[0]) << 8) | int.Parse(tokens[1]);
						val[index++] = (int.Parse(tokens[2]) << 8) | int.Parse(tokens[3]);
					}
				}
			}

			if (index != val.Length)
			{
				Array.Copy(val, doubleColon, val, val.Length - (index - doubleColon), index - doubleColon);
				for (int i = doubleColon; i != val.Length - (index - doubleColon); i++)
				{
					val[i] = 0;
				}
			}

			return val;
		}

        private static int[] ParseIPv6Mask(string mask)
        {
            int[] res = new int[8];

			int bits = int.Parse(mask), resPos = 0;
			while (bits >= 16)
			{
				res[resPos++] = ushort.MaxValue;
				bits -= 16;
			}
			if (bits > 0)
			{
				res[resPos] = ushort.MaxValue >> (16 - bits);
			}

			return res;
        }
    }
}
