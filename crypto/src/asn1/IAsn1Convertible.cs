namespace Org.BouncyCastle.Asn1
{
    // TODO[api] Make generic on the return type of ToAsn1Object()
    // TODO[api] Have a different interface that is only for custom ASN.1 types
    public interface IAsn1Convertible
	{
		Asn1Object ToAsn1Object();
	}
}
