using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    // TODO[api] Make static
    public abstract class OcspObjectIdentifiers
    {
		public static readonly DerObjectIdentifier PkixOcsp = new DerObjectIdentifier("1.3.6.1.5.5.7.48.1");

        public static readonly DerObjectIdentifier PkixOcspBasic = PkixOcsp.Branch("1");

		//
		// extensions
		//
		public static readonly DerObjectIdentifier PkixOcspNonce = PkixOcsp.Branch("2");
		public static readonly DerObjectIdentifier PkixOcspCrl = PkixOcsp.Branch("3");

		public static readonly DerObjectIdentifier PkixOcspResponse = PkixOcsp.Branch("4");
		public static readonly DerObjectIdentifier PkixOcspNocheck = PkixOcsp.Branch("5");
		public static readonly DerObjectIdentifier PkixOcspArchiveCutoff = PkixOcsp.Branch("6");
		public static readonly DerObjectIdentifier PkixOcspServiceLocator = PkixOcsp.Branch("7");
	}
}
