using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
	public class BerTaggedObjectParser
		: Asn1TaggedObjectParser
	{
        private readonly int m_tagClass;
        private readonly int m_tagNo;
        private readonly bool m_constructed;
        private readonly Asn1StreamParser m_parser;

		internal BerTaggedObjectParser(int tagClass, int tagNo, bool constructed, Asn1StreamParser parser)
		{
            this.m_tagClass = tagClass;
            this.m_tagNo = tagNo;
            this.m_constructed = constructed;
            this.m_parser = parser;
		}

		public bool IsConstructed
		{
			get { return m_constructed; }
		}

        public int TagClass
        {
            get { return m_tagClass; }
        }

		public int TagNo
		{
			get { return m_tagNo; }
		}

		public IAsn1Convertible GetObjectParser(int baseTagNo, bool declaredExplicit)
		{
            if (Asn1Tags.ContextSpecific != TagClass)
                throw new Asn1Exception("this method only valid for CONTEXT_SPECIFIC tags");

            if (!declaredExplicit)
                return m_parser.ReadImplicit(m_constructed, baseTagNo);

			if (!m_constructed)
				throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");

	        return m_parser.ReadObject();
		}

		public Asn1Object ToAsn1Object()
		{
			try
			{
				return m_parser.ReadTaggedObject(TagClass, TagNo, IsConstructed);
			}
			catch (IOException e)
			{
				throw new Asn1ParsingException(e.Message);
			}
		}
	}
}
