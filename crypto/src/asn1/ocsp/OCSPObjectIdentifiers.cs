using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>Object identifiers for OCSP (RFC 6960).</summary>
    // TODO[api] Make static
    public abstract class OcspObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcsp = X509ObjectIdentifiers.IdADOcsp;

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.1</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcspBasic = PkixOcsp.Branch("1");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.2</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcspNonce = PkixOcsp.Branch("2");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.3</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcspCrl = PkixOcsp.Branch("3");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.4</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcspResponse = PkixOcsp.Branch("4");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.5</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcspNocheck = PkixOcsp.Branch("5");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.6</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcspArchiveCutoff = PkixOcsp.Branch("6");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.7</c>.</summary>
        public static readonly DerObjectIdentifier PkixOcspServiceLocator = PkixOcsp.Branch("7");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.8</c>.</summary>
        public static readonly DerObjectIdentifier PkixPcspPrefSigSlgs = PkixOcsp.Branch("8");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1.9</c>.</summary>
        public static readonly DerObjectIdentifier PkixPcspExtendedRevoke = PkixOcsp.Branch("9");
    }
}
