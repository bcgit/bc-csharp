using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    // TODO[api] Make static
    public abstract class OcspObjectIdentifiers
    {
		public static readonly DerObjectIdentifier PkixOcsp = X509ObjectIdentifiers.IdADOcsp;

        public static readonly DerObjectIdentifier PkixOcspBasic = PkixOcsp.Branch("1");
		public static readonly DerObjectIdentifier PkixOcspNonce = PkixOcsp.Branch("2");
		public static readonly DerObjectIdentifier PkixOcspCrl = PkixOcsp.Branch("3");
		public static readonly DerObjectIdentifier PkixOcspResponse = PkixOcsp.Branch("4");
		public static readonly DerObjectIdentifier PkixOcspNocheck = PkixOcsp.Branch("5");
		public static readonly DerObjectIdentifier PkixOcspArchiveCutoff = PkixOcsp.Branch("6");
		public static readonly DerObjectIdentifier PkixOcspServiceLocator = PkixOcsp.Branch("7");
        public static readonly DerObjectIdentifier PkixPcspPrefSigSlgs = PkixOcsp.Branch("8");
		public static readonly DerObjectIdentifier PkixPcspExtendedRevoke = PkixOcsp.Branch("9");
	}
}
