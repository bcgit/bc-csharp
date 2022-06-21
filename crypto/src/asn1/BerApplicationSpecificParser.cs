using System;

namespace Org.BouncyCastle.Asn1
{
	internal class BerApplicationSpecificParser
		: BerTaggedObjectParser, IAsn1ApplicationSpecificParser
	{
		internal BerApplicationSpecificParser(int tagNo, Asn1StreamParser parser)
            : base(Asn1Tags.Application, tagNo, parser)
		{
		}

		public IAsn1Convertible ReadObject()
		{
            // NOTE: No way to say you're looking for an implicitly-tagged object via IAsn1ApplicationSpecificParser
            return ParseExplicitBaseObject();
        }
	}
}
