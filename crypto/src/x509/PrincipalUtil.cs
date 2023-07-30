using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.X509
{
    /// <remarks>
    /// A utility class that will extract X509Principal objects from X.509 certificates.
    /// <p>
    /// Use this in preference to trying to recreate a principal from a string, not all
    /// DNs are what they should be, so it's best to leave them encoded where they
    /// can be.</p>
    /// </remarks>
    // TODO[api] Make static
    public class PrincipalUtilities
	{
		/// <summary>Return the issuer of the given cert as an X509Principal.</summary>
		public static X509Name GetIssuerX509Principal(X509Certificate cert)
		{
            return cert.TbsCertificate.Issuer;
		}

		/// <summary>Return the subject of the given cert as an X509Principal.</summary>
		public static X509Name GetSubjectX509Principal(X509Certificate cert)
		{
            return cert.TbsCertificate.Subject;
		}

		/// <summary>Return the issuer of the given CRL as an X509Principal.</summary>
		public static X509Name GetIssuerX509Principal(X509Crl crl)
		{
			return crl.CertificateList.TbsCertList.Issuer;
		}
	}
}
