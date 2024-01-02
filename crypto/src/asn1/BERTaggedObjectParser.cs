using System.IO;

namespace Org.BouncyCastle.Asn1
{
    internal class BerTaggedObjectParser
		: Asn1TaggedObjectParser
	{
        internal readonly int m_tagClass;
        internal readonly int m_tagNo;
        internal readonly Asn1StreamParser m_parser;

		internal BerTaggedObjectParser(int tagClass, int tagNo, Asn1StreamParser parser)
		{
            m_tagClass = tagClass;
            m_tagNo = tagNo;
            m_parser = parser;
		}

        public virtual bool IsConstructed => true;

        public int TagClass => m_tagClass;

		public int TagNo => m_tagNo;

        public bool HasContextTag()
        {
            return m_tagClass == Asn1Tags.ContextSpecific;
        }

        public bool HasContextTag(int tagNo)
        {
            return m_tagClass == Asn1Tags.ContextSpecific && m_tagNo == tagNo;
        }

        public bool HasTag(int tagClass, int tagNo)
        {
            return m_tagClass == tagClass && m_tagNo == tagNo;
        }

        public bool HasTagClass(int tagClass)
        {
            return m_tagClass == tagClass;
        }

        public virtual IAsn1Convertible ParseBaseUniversal(bool declaredExplicit, int baseTagNo)
        {
            if (declaredExplicit)
                return m_parser.ParseObject(baseTagNo);

            return m_parser.ParseImplicitConstructedIL(baseTagNo);
        }

        public virtual IAsn1Convertible ParseExplicitBaseObject() => m_parser.ReadObject();

        public virtual Asn1TaggedObjectParser ParseExplicitBaseTagged() => m_parser.ParseTaggedObject();

        public virtual Asn1TaggedObjectParser ParseImplicitBaseTagged(int baseTagClass, int baseTagNo) =>
            new BerTaggedObjectParser(baseTagClass, baseTagNo, m_parser);

        public virtual Asn1Object ToAsn1Object()
		{
			try
			{
                return m_parser.LoadTaggedIL(TagClass, TagNo);
            }
			catch (IOException e)
			{
				throw new Asn1ParsingException(e.Message);
			}
		}
	}
}
