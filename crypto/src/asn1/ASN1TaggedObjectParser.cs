namespace Org.BouncyCastle.Asn1
{
	public interface Asn1TaggedObjectParser
		: IAsn1Convertible
	{
        int TagClass { get; }

		int TagNo { get; }

		IAsn1Convertible GetObjectParser(int tag, bool isExplicit);
	}
}
