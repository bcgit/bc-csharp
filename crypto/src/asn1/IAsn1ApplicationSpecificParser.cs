using System;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Test for Asn1TaggedObjectParser with TagClass of Asn1Tags.Application instead")]
	public interface IAsn1ApplicationSpecificParser
    	: Asn1TaggedObjectParser
    {
    	IAsn1Convertible ReadObject();
	}
}
