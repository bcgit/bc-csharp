using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    public class CertificateID
		: IEquatable<CertificateID>
	{
        // OiwObjectIdentifiers.IdSha1.Id
		public const string HashSha1 = "1.3.14.3.2.26";

		private readonly CertID m_id;

		public CertificateID(CertID id)
		{
			m_id = id ?? throw new ArgumentNullException(nameof(id));
		}

		/**
		 * create from an issuer certificate and the serial number of the
		 * certificate it signed.
		 * @exception OcspException if any problems occur creating the id fields.
		 */
		public CertificateID(string hashAlgorithm, X509Certificate issuerCert, BigInteger serialNumber)
		{
			AlgorithmIdentifier hashAlg = new AlgorithmIdentifier(
				new DerObjectIdentifier(hashAlgorithm), DerNull.Instance);

			m_id = CreateCertID(hashAlg, issuerCert, new DerInteger(serialNumber));
		}

		public string HashAlgOid => m_id.HashAlgorithm.Algorithm.Id;

		public byte[] GetIssuerNameHash() => m_id.IssuerNameHash.GetOctets();

		public byte[] GetIssuerKeyHash() => m_id.IssuerKeyHash.GetOctets();

		/**
		 * return the serial number for the certificate associated
		 * with this request.
		 */
		public BigInteger SerialNumber => m_id.SerialNumber.Value;

		public bool MatchesIssuer(X509Certificate issuerCert)
		{
			return CreateCertID(m_id.HashAlgorithm, issuerCert, m_id.SerialNumber).Equals(m_id);
		}

        public CertID ToAsn1Object() => m_id;

        public bool Equals(CertificateID other) => this == other || m_id.Equals(other?.m_id);

        public override bool Equals(object obj) => Equals(obj as CertificateID);

        public override int GetHashCode() => m_id.GetHashCode();

		/**
		 * Create a new CertificateID for a new serial number derived from a previous one
		 * calculated for the same CA certificate.
		 *
		 * @param original the previously calculated CertificateID for the CA.
		 * @param newSerialNumber the serial number for the new certificate of interest.
		 *
		 * @return a new CertificateID for newSerialNumber
		 */
		public static CertificateID DeriveCertificateID(CertificateID original, BigInteger newSerialNumber)
		{
            CertID originalID = original.ToAsn1Object();

            return new CertificateID(new CertID(originalID.HashAlgorithm, originalID.IssuerNameHash,
                originalID.IssuerKeyHash, new DerInteger(newSerialNumber)));
		}

        private static CertID CreateCertID(AlgorithmIdentifier digestAlgorithm, X509Certificate issuerCert,
			DerInteger serialNumber)
		{
			try
			{
				X509Name issuerName = PrincipalUtilities.GetSubjectX509Principal(issuerCert);
				byte[] issuerNameHash = X509Utilities.CalculateDigest(digestAlgorithm, issuerName);

				byte[] issuerKey = issuerCert.SubjectPublicKeyInfo.PublicKey.GetBytes();
				byte[] issuerKeyHash = DigestUtilities.CalculateDigest(digestAlgorithm.Algorithm, issuerKey);

                return new CertID(digestAlgorithm, new DerOctetString(issuerNameHash),
					new DerOctetString(issuerKeyHash), serialNumber);
			}
			catch (Exception e)
			{
				throw new OcspException("problem creating ID: " + e, e);
			}
		}
	}
}
