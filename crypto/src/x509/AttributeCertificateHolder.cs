using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.X509
{
    /// <remarks>
    /// The Holder object.
    /// <pre>
    /// Holder ::= SEQUENCE {
    ///		baseCertificateID   [0] IssuerSerial OPTIONAL,
    ///			-- the issuer and serial number of
    ///			-- the holder's Public Key Certificate
    ///		entityName          [1] GeneralNames OPTIONAL,
    ///			-- the name of the claimant or role
    ///		objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
    ///			-- used to directly authenticate the holder,
    ///			-- for example, an executable
    /// }
    /// </pre>
    /// </remarks>
    public class AttributeCertificateHolder
		: IEquatable<AttributeCertificateHolder>, ISelector<X509Certificate>
	{
		internal readonly Holder m_holder;

		internal AttributeCertificateHolder(Asn1Sequence seq)
		{
			m_holder = Holder.GetInstance(seq);
		}

		public AttributeCertificateHolder(X509Name issuerName, BigInteger serialNumber)
		{
			m_holder = new Holder(
				new IssuerSerial(
					GenerateGeneralNames(issuerName),
					new DerInteger(serialNumber)));
		}

		public AttributeCertificateHolder(X509Certificate cert)
		{
			m_holder = new Holder(
				new IssuerSerial(
					GenerateGeneralNames(cert.IssuerDN),
					new DerInteger(cert.SerialNumber)));
		}

		public AttributeCertificateHolder(X509Name principal)
		{
			m_holder = new Holder(GenerateGeneralNames(principal));
		}

		/**
		 * Constructs a holder for v2 attribute certificates with a hash value for
		 * some type of object.
		 * <p>
		 * <code>digestedObjectType</code> can be one of the following:
		 * <ul>
		 * <li>0 - publicKey - A hash of the public key of the holder must be
		 * passed.</li>
		 * <li>1 - publicKeyCert - A hash of the public key certificate of the
		 * holder must be passed.</li>
		 * <li>2 - otherObjectDigest - A hash of some other object type must be
		 * passed. <code>otherObjectTypeID</code> must not be empty.</li>
		 * </ul>
		 * </p>
		 * <p>This cannot be used if a v1 attribute certificate is used.</p>
		 *
		 * @param digestedObjectType The digest object type.
		 * @param digestAlgorithm The algorithm identifier for the hash.
		 * @param otherObjectTypeID The object type ID if
		 *            <code>digestedObjectType</code> is
		 *            <code>otherObjectDigest</code>.
		 * @param objectDigest The hash value.
		 */
		public AttributeCertificateHolder(int digestedObjectType, string digestAlgorithm, string otherObjectTypeID,
			byte[] objectDigest)
		{
			var digestAlgorithmID = new AlgorithmIdentifier(new DerObjectIdentifier(digestAlgorithm));
			var objectDigestInfo = new ObjectDigestInfo(digestedObjectType, otherObjectTypeID, digestAlgorithmID,
				Arrays.Clone(objectDigest));

            m_holder = new Holder(objectDigestInfo);
		}

		/**
		 * Returns the digest object type if an object digest info is used.
		 * <p>
		 * <ul>
		 * <li>0 - publicKey - A hash of the public key of the holder must be
		 * passed.</li>
		 * <li>1 - publicKeyCert - A hash of the public key certificate of the
		 * holder must be passed.</li>
		 * <li>2 - otherObjectDigest - A hash of some other object type must be
		 * passed. <code>otherObjectTypeID</code> must not be empty.</li>
		 * </ul>
		 * </p>
		 *
		 * @return The digest object type or -1 if no object digest info is set.
		 */
		public int DigestedObjectType
		{
			get
			{
				ObjectDigestInfo odi = m_holder.ObjectDigestInfo;

				return odi == null
					?   -1
                    :   odi.DigestedObjectType.IntValueExact;
			}
		}

		/**
		 * Returns the other object type ID if an object digest info is used.
		 *
		 * @return The other object type ID or <code>null</code> if no object
		 *         digest info is set.
		 */
		public string DigestAlgorithm => m_holder.ObjectDigestInfo?.DigestAlgorithm.Algorithm.Id;

		/**
		 * Returns the hash if an object digest info is used.
		 *
		 * @return The hash or <code>null</code> if no object digest info is set.
		 */
		public byte[] GetObjectDigest() => m_holder.ObjectDigestInfo?.ObjectDigest.GetBytes();

		/**
		 * Returns the digest algorithm ID if an object digest info is used.
		 *
		 * @return The digest algorithm ID or <code>null</code> if no object
		 *         digest info is set.
		 */
		public string OtherObjectTypeID => m_holder.ObjectDigestInfo?.OtherObjectTypeID.Id;

		private GeneralNames GenerateGeneralNames(X509Name principal) => new GeneralNames(new GeneralName(principal));

		private bool MatchesDN(X509Name subject, GeneralNames targets)
		{
			foreach (var gn in targets.GetNames())
			{
				if (gn.TagNo == GeneralName.DirectoryName)
				{
					try
					{
						if (X509Name.GetInstance(gn.Name).Equivalent(subject))
							return true;
					}
					catch (Exception)
					{
					}
				}
			}

			return false;
		}

		private X509Name[] GetPrincipals(GeneralNames generalNames)
		{
			var names = generalNames.GetNames();
			var result = new List<X509Name>(names.Length);
			foreach (var name in names)
            {
                if (GeneralName.DirectoryName == name.TagNo)
                {
					result.Add(X509Name.GetInstance(name.Name));
                }
			}
			return result.ToArray();
        }

		/**
		 * Return any principal objects inside the attribute certificate holder entity names field.
		 *
		 * @return an array of IPrincipal objects (usually X509Name), null if no entity names field is set.
		 */
		public X509Name[] GetEntityNames()
		{
			var entityName = m_holder.EntityName;
			return entityName == null ? null : GetPrincipals(entityName);
		}

		/**
		 * Return the principals associated with the issuer attached to this holder
		 *
		 * @return an array of principals, null if no BaseCertificateID is set.
		 */
		public X509Name[] GetIssuer()
		{
			var baseCertificateID = m_holder.BaseCertificateID;
			return baseCertificateID == null ? null : GetPrincipals(baseCertificateID.Issuer);
		}

		/**
		 * Return the serial number associated with the issuer attached to this holder.
		 *
		 * @return the certificate serial number, null if no BaseCertificateID is set.
		 */
		public BigInteger SerialNumber => m_holder.BaseCertificateID?.Serial.Value;

		public object Clone() => new AttributeCertificateHolder((Asn1Sequence)m_holder.ToAsn1Object());

		public bool Match(X509Certificate x509Cert)
		{
			if (x509Cert == null)
				return false;

			try
			{
                var baseCertificateID = m_holder.BaseCertificateID;
                if (baseCertificateID != null)
				{
					return baseCertificateID.Serial.HasValue(x509Cert.SerialNumber)
						&& MatchesDN(x509Cert.IssuerDN, baseCertificateID.Issuer);
				}

				var entityName = m_holder.EntityName;
				if (entityName != null)
				{
					if (MatchesDN(x509Cert.SubjectDN, entityName))
						return true;
				}

				var objectDigestInfo = m_holder.ObjectDigestInfo;
				if (objectDigestInfo != null)
				{
					IDigest md = DigestUtilities.GetDigest(DigestAlgorithm);

					switch (objectDigestInfo.DigestedObjectType.IntValueExact)
					{
					case ObjectDigestInfo.PublicKey:
					{
						// TODO: DSA Dss-parms
						byte[] b = x509Cert.SubjectPublicKeyInfo.GetEncoded();
						md.BlockUpdate(b, 0, b.Length);
						break;
					}
					case ObjectDigestInfo.PublicKeyCert:
					{
						byte[] b = x509Cert.GetEncoded();
						md.BlockUpdate(b, 0, b.Length);
						break;
					}
					// TODO Default handler?
					}

					if (Arrays.AreEqual(GetObjectDigest(), DigestUtilities.DoFinal(md)))
						return true;
				}
			}
			catch (Exception)
			{
			}

			return false;
		}

		public virtual bool Equals(AttributeCertificateHolder other)
		{
            return this == other || m_holder.Equals(other?.m_holder);
        }

		public override bool Equals(object obj) => Equals(obj as AttributeCertificateHolder);

		public override int GetHashCode() => m_holder.GetHashCode();
	}
}
