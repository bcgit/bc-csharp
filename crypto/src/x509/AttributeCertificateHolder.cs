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
    ///     baseCertificateID   [0] IssuerSerial OPTIONAL,
    ///         -- the issuer and serial number of
    ///         -- the holder's Public Key Certificate
    ///     entityName          [1] GeneralNames OPTIONAL,
    ///         -- the name of the claimant or role
    ///     objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
    ///         -- used to directly authenticate the holder,
    ///         -- for example, an executable
    /// }
    /// </pre>
    /// </remarks>
    /// <summary>The holder of an attribute certificate: the entity the attributes are assigned to.</summary>
    public class AttributeCertificateHolder
        : IEquatable<AttributeCertificateHolder>, ISelector<X509Certificate>
    {
        internal readonly Holder m_holder;

        internal AttributeCertificateHolder(Asn1Sequence seq)
        {
            m_holder = Holder.GetInstance(seq);
        }

        /// <summary>Create a holder identified by the issuer and serial number of its public key certificate.</summary>
        /// <param name="issuerName">The issuer of the holder's certificate.</param>
        /// <param name="serialNumber">The serial number of the holder's certificate.</param>
        public AttributeCertificateHolder(X509Name issuerName, BigInteger serialNumber)
            : this(issuerName, new DerInteger(serialNumber))
        {
        }

        /// <summary>Create a holder identified by the issuer and serial number of its public key certificate.</summary>
        /// <param name="issuerName">The issuer of the holder's certificate.</param>
        /// <param name="serialNumber">The serial number of the holder's certificate.</param>
        public AttributeCertificateHolder(X509Name issuerName, DerInteger serialNumber)
        {
            m_holder = new Holder(new IssuerSerial(issuerName, serialNumber));
        }

        /// <summary>Create a holder identified by its public key certificate.</summary>
        /// <param name="cert">The holder's certificate.</param>
        public AttributeCertificateHolder(X509Certificate cert)
        {
            m_holder = new Holder(X509Utilities.CreateIssuerSerial(cert));
        }

        /// <summary>Create a holder identified by a name.</summary>
        /// <param name="principal">The name of the holder.</param>
        public AttributeCertificateHolder(X509Name principal)
        {
            m_holder = new Holder(new GeneralNames(new GeneralName(principal)));
        }

        /// <summary>Constructs a holder for v2 attribute certificates with a hash value for some type of object.
        /// </summary>
        /// <remarks>
        /// <paramref name="digestedObjectType"/> can be one of the following:
        /// <list type="bullet">
        /// <item>0 - publicKey - A hash of the public key of the holder must be passed.</item>
        /// <item>1 - publicKeyCert - A hash of the public key certificate of the holder must be passed.</item>
        /// <item>2 - otherObjectDigest - A hash of some other object type must be passed.
        /// <paramref name="otherObjectTypeID"/> must not be empty.</item>
        /// </list>
        /// This cannot be used if a v1 attribute certificate is used.
        /// </remarks>
        /// <param name="digestedObjectType">The digest object type.</param>
        /// <param name="digestAlgorithm">The algorithm identifier for the hash.</param>
        /// <param name="otherObjectTypeID">The object type ID if <paramref name="digestedObjectType"/> is
        /// otherObjectDigest.</param>
        /// <param name="objectDigest">The hash value.</param>
        public AttributeCertificateHolder(int digestedObjectType, string digestAlgorithm, string otherObjectTypeID,
            byte[] objectDigest)
        {
            var digestAlgorithmID = new AlgorithmIdentifier(new DerObjectIdentifier(digestAlgorithm));
            var objectDigestInfo = new ObjectDigestInfo(digestedObjectType, otherObjectTypeID, digestAlgorithmID,
                Arrays.Clone(objectDigest));

            m_holder = new Holder(objectDigestInfo);
        }

        /// <summary>Returns the digest object type if an object digest info is used.</summary>
        /// <remarks>
        /// The possible values are:
        /// <list type="bullet">
        /// <item>0 - publicKey - A hash of the public key of the holder.</item>
        /// <item>1 - publicKeyCert - A hash of the public key certificate of the holder.</item>
        /// <item>2 - otherObjectDigest - A hash of some other object type; see <see cref="OtherObjectTypeID"/>.</item>
        /// </list>
        /// </remarks>
        /// <returns>The digest object type or -1 if no object digest info is set.</returns>
        public int DigestedObjectType
        {
            get
            {
                ObjectDigestInfo odi = m_holder.ObjectDigestInfo;

                return odi == null
                    ? -1
                    : odi.DigestedObjectType.IntValueExact;
            }
        }

        /// <summary>Returns the digest algorithm ID if an object digest info is used.</summary>
        /// <returns>The digest algorithm ID or <c>null</c> if no object digest info is set.</returns>
        public string DigestAlgorithm => m_holder.ObjectDigestInfo?.DigestAlgorithm.Algorithm.Id;

        /// <summary>Returns the hash if an object digest info is used.</summary>
        /// <returns>The hash or <c>null</c> if no object digest info is set.</returns>
        public byte[] GetObjectDigest() => m_holder.ObjectDigestInfo?.ObjectDigest.GetBytes();

        /// <summary>Returns the other object type ID if an object digest info is used.</summary>
        /// <returns>The other object type ID or <c>null</c> if no object digest info is set.</returns>
        public string OtherObjectTypeID => m_holder.ObjectDigestInfo?.OtherObjectTypeID.Id;

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

        /// <summary>Return the names inside the attribute certificate holder entity names field.</summary>
        /// <returns>An array of names, or null if no entity names field is set.</returns>
        public X509Name[] GetEntityNames()
        {
            var entityName = m_holder.EntityName;
            return entityName == null ? null : GetPrincipals(entityName);
        }

        /// <summary>Return the names of the issuer attached to this holder.</summary>
        /// <returns>An array of names, or null if no BaseCertificateID is set.</returns>
        public X509Name[] GetIssuer()
        {
            var baseCertificateID = m_holder.BaseCertificateID;
            return baseCertificateID == null ? null : GetPrincipals(baseCertificateID.Issuer);
        }

        /// <summary>Return the serial number associated with the issuer attached to this holder.</summary>
        /// <returns>the certificate serial number, null if no BaseCertificateID is set.</returns>
        public BigInteger SerialNumber => m_holder.BaseCertificateID?.Serial.Value;

        /// <summary>Return a copy of this holder.</summary>
        public object Clone() => new AttributeCertificateHolder((Asn1Sequence)m_holder.ToAsn1Object());

        /// <summary>Test whether the given certificate is the holder's certificate.</summary>
        /// <remarks>
        /// The certificate is matched against the base certificate ID if there is one, otherwise against the entity
        /// name and then the object digest.
        /// </remarks>
        /// <param name="x509Cert">The certificate to test.</param>
        /// <returns>true if the certificate matches, false otherwise or if it is null.</returns>
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

        /// <summary>Two holders are equal if their underlying ASN.1 structures are equal.</summary>
        public virtual bool Equals(AttributeCertificateHolder other)
        {
            return this == other || m_holder.Equals(other?.m_holder);
        }

        /// <summary>Two holders are equal if their underlying ASN.1 structures are equal.</summary>
        public override bool Equals(object obj) => Equals(obj as AttributeCertificateHolder);

        /// <summary>Returns a hash code derived from the underlying ASN.1 structure.</summary>
        public override int GetHashCode() => m_holder.GetHashCode();
    }
}
