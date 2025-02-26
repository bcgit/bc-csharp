using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.X509.Store
{
    public class X509CertStoreSelector
        : ISelector<X509Certificate>
    {
        // TODO Missing criteria?

        private byte[] m_authorityKeyIdentifier;
        private int m_basicConstraints = -1;
        private X509Certificate m_certificate;
        private DateTime? m_certificateValid;
        private ISet<DerObjectIdentifier> m_extendedKeyUsage;
        private bool m_ignoreX509NameOrdering;
        private X509Name m_issuer;
        private bool[] m_keyUsage;
        private bool m_matchAllSubjectAltNames = true;
        private ISet<DerObjectIdentifier> m_policy;
        private DateTime? m_privateKeyValid;
        private BigInteger m_serialNumber;
        private X509Name m_subject;
        private ISet<GeneralName> m_subjectAlternativeNames;
        private byte[] m_subjectKeyIdentifier;
        private SubjectPublicKeyInfo m_subjectPublicKey;
        private DerObjectIdentifier m_subjectPublicKeyAlgID;

        public X509CertStoreSelector()
        {
        }

        public X509CertStoreSelector(X509CertStoreSelector o)
        {
            m_authorityKeyIdentifier = o.m_authorityKeyIdentifier;
            m_basicConstraints = o.m_basicConstraints;
            m_certificate = o.m_certificate;
            m_certificateValid = o.m_certificateValid;
            m_extendedKeyUsage = o.m_extendedKeyUsage;
            m_ignoreX509NameOrdering = o.m_ignoreX509NameOrdering;
            m_issuer = o.m_issuer;
            m_keyUsage = o.m_keyUsage;
            m_matchAllSubjectAltNames = o.m_matchAllSubjectAltNames;
            m_policy = o.m_policy;
            m_privateKeyValid = o.m_privateKeyValid;
            m_serialNumber = o.m_serialNumber;
            m_subject = o.m_subject;
            m_subjectAlternativeNames = o.m_subjectAlternativeNames;
            m_subjectKeyIdentifier = o.m_subjectKeyIdentifier;
            m_subjectPublicKey = o.m_subjectPublicKey;
            m_subjectPublicKeyAlgID = o.m_subjectPublicKeyAlgID;
        }

        public virtual object Clone()
        {
            return new X509CertStoreSelector(this);
        }

        /// <remarks>
		/// A DER encoding of an ASN.1 AuthorityKeyIdentifier value.
        /// </remarks>
		public byte[] AuthorityKeyIdentifier
        {
            get { return Arrays.Clone(m_authorityKeyIdentifier); }
            set { m_authorityKeyIdentifier = Arrays.Clone(value); }
        }

        public int BasicConstraints
        {
            get { return m_basicConstraints; }
            set { m_basicConstraints = CheckBasicConstraints(value); }
        }

        public X509Certificate Certificate
        {
            get { return m_certificate; }
            set { m_certificate = value; }
        }

        public DateTime? CertificateValid
        {
            get { return m_certificateValid; }
            set { m_certificateValid = value; }
        }

        public ISet<DerObjectIdentifier> ExtendedKeyUsage
        {
            get { return CopySet(m_extendedKeyUsage); }
            set { m_extendedKeyUsage = CopySet(value); }
        }

        public bool IgnoreX509NameOrdering
        {
            get { return m_ignoreX509NameOrdering; }
            set { m_ignoreX509NameOrdering = value; }
        }

        public X509Name Issuer
        {
            get { return m_issuer; }
            set { m_issuer = value; }
        }

        public bool[] KeyUsage
        {
            get { return Arrays.Clone(m_keyUsage); }
            set { m_keyUsage = Arrays.Clone(value); }
        }

        public bool MatchAllSubjectAltNames
        {
            get { return m_matchAllSubjectAltNames; }
            set { m_matchAllSubjectAltNames = value; }
        }

        public ISet<DerObjectIdentifier> Policy
        {
            get { return CopySet(m_policy); }
            set { m_policy = CopySet(value); }
        }

        public DateTime? PrivateKeyValid
        {
            get { return m_privateKeyValid; }
            set { m_privateKeyValid = value; }
        }

        public BigInteger SerialNumber
        {
            get { return m_serialNumber; }
            set { m_serialNumber = value; }
        }

        public X509Name Subject
        {
            get { return m_subject; }
            set { m_subject = value; }
        }

        public ISet<GeneralName> SubjectAlternativeNames
        {
            get { return CopySet(m_subjectAlternativeNames); }
            set { m_subjectAlternativeNames = CopySet(value); }
        }

        /// <remarks>
		/// A DER encoding of an ASN.1 SubjectKeyIdentifier (OCTET STRING) value.
        /// </remarks>
        public byte[] SubjectKeyIdentifier
        {
            get { return Arrays.Clone(m_subjectKeyIdentifier); }
            set { m_subjectKeyIdentifier = Arrays.Clone(value); }
        }

        public SubjectPublicKeyInfo SubjectPublicKey
        {
            get { return m_subjectPublicKey; }
            set { m_subjectPublicKey = value; }
        }

        public DerObjectIdentifier SubjectPublicKeyAlgID
        {
            get { return m_subjectPublicKeyAlgID; }
            set { m_subjectPublicKeyAlgID = value; }
        }

        public virtual bool Match(X509Certificate c)
        {
            if (c == null)
                return false;

            if (m_certificate != null && !m_certificate.Equals(c))
                return false;

            if (m_serialNumber != null && !m_serialNumber.Equals(c.SerialNumber))
                return false;

            if (m_issuer != null && !m_issuer.Equivalent(c.IssuerDN, !m_ignoreX509NameOrdering))
                return false;

            if (m_subject != null && !m_subject.Equivalent(c.SubjectDN, !m_ignoreX509NameOrdering))
                return false;

            if (m_certificateValid != null && !c.IsValid(m_certificateValid.Value))
                return false;

            if (m_subjectPublicKey != null && !m_subjectPublicKey.Equals(c.SubjectPublicKeyInfo))
                return false;

            if (m_basicConstraints != -1 && !MatchBasicConstraints(c))
                return false;

            if (m_keyUsage != null && !MatchKeyUsage(c))
                return false;

            if (!CollectionUtilities.IsNullOrEmpty(m_extendedKeyUsage) && !MatchExtendedKeyUsage(c))
                return false;

            if (!MatchExtension(m_subjectKeyIdentifier, c, X509Extensions.SubjectKeyIdentifier))
                return false;

            if (!MatchExtension(m_authorityKeyIdentifier, c, X509Extensions.AuthorityKeyIdentifier))
                return false;

            if (m_privateKeyValid != null && !MatchPrivateKeyValid(c))
                return false;

            if (m_subjectPublicKeyAlgID != null && !m_subjectPublicKeyAlgID.Equals(c.SubjectPublicKeyInfo.Algorithm))
                return false;

            if (m_policy != null && !MatchPolicy(c))
                return false;

            if (!CollectionUtilities.IsNullOrEmpty(m_subjectAlternativeNames) && !MatchSubjectAlternativeNames(c))
                return false;

            return true;
        }

        protected internal int GetHashCodeOfSubjectKeyIdentifier() => Arrays.GetHashCode(m_subjectKeyIdentifier);

        protected internal bool MatchesIssuer(X509CertStoreSelector other) => IssuersMatch(m_issuer, other.m_issuer);

        protected internal bool MatchesSerialNumber(X509CertStoreSelector other) =>
            Objects.Equals(m_serialNumber, other.m_serialNumber);

        protected internal bool MatchesSubjectKeyIdentifier(X509CertStoreSelector other) =>
            Arrays.AreEqual(m_subjectKeyIdentifier, other.m_subjectKeyIdentifier);

        private static bool IssuersMatch(X509Name a, X509Name b)
        {
            return a == null ? b == null : a.Equivalent(b, true);
        }

        private static ISet<T> CopySet<T>(ISet<T> s)
        {
            return s == null ? null : new HashSet<T>(s);
        }

        private static int CheckBasicConstraints(int basicConstraints)
        {
            if (basicConstraints < -2)
                throw new ArgumentException("can't be less than -2", nameof(basicConstraints));

            return basicConstraints;
        }

        private bool MatchBasicConstraints(X509Certificate c)
        {
            int maxPathLen = c.GetBasicConstraints();

            if (m_basicConstraints == -2)
                return maxPathLen == -1;

            return maxPathLen >= m_basicConstraints;
        }

        private bool MatchExtendedKeyUsage(X509Certificate c)
        {
            IList<DerObjectIdentifier> eku = c.GetExtendedKeyUsage();
            if (eku != null && !eku.Contains(KeyPurposeID.AnyExtendedKeyUsage))
            {
                foreach (DerObjectIdentifier oid in m_extendedKeyUsage)
                {
                    if (!eku.Contains(oid))
                        return false;
                }
            }
            return true;
        }

        private bool MatchKeyUsage(X509Certificate c)
        {
            bool[] ku = c.GetKeyUsage();
            if (ku != null)
            {
                for (int i = 0; i < m_keyUsage.Length; ++i)
                {
                    if (m_keyUsage[i] && (i >= ku.Length || !ku[i]))
                        return false;
                }
            }
            return true;
        }

        private bool MatchPolicy(X509Certificate c)
        {
            Asn1Sequence certificatePolicies = Asn1Sequence.GetInstance(
                X509ExtensionUtilities.FromExtensionValue(c, X509Extensions.CertificatePolicies));

            if (certificatePolicies == null || certificatePolicies.Count < 1)
                return false;

            return m_policy.Count < 1 || PoliciesIntersect(m_policy, certificatePolicies);
        }

        private bool MatchPrivateKeyValid(X509Certificate c)
        {
            var privateKeyUsagePeriod = PrivateKeyUsagePeriod.GetInstance(
                X509ExtensionUtilities.FromExtensionValue(c, X509Extensions.PrivateKeyUsagePeriod));

            if (privateKeyUsagePeriod != null)
            {
                var validityUtc = m_privateKeyValid.Value.ToUniversalTime();

                var notBefore = privateKeyUsagePeriod.NotBefore;
                if (notBefore != null)
                {
                    var notBeforeUtc = notBefore.ToDateTime().ToUniversalTime();

                    // NOTE: DateTime.CompareTo ignores DateTimeKind, so ensure we compare UTC values
                    if (notBeforeUtc.CompareTo(validityUtc) > 0)
                        return false;
                }

                var notAfter = privateKeyUsagePeriod.NotAfter;
                if (notAfter != null)
                {
                    var notAfterUtc = notAfter.ToDateTime().ToUniversalTime();

                    // NOTE: DateTime.CompareTo ignores DateTimeKind, so ensure we compare UTC values
                    if (notAfterUtc.CompareTo(validityUtc) < 0)
                        return false;
                }
            }

            return true;
        }

        private bool MatchSubjectAlternativeNames(X509Certificate c)
        {
            GeneralNames generalNames = GeneralNames.GetInstance(
                X509ExtensionUtilities.FromExtensionValue(c, X509Extensions.SubjectAlternativeName));

            if (generalNames == null)
                return false;

            GeneralName[] names = generalNames.GetNames();

            foreach (var name in m_subjectAlternativeNames)
            {
                bool match = ContainsGeneralName(names, name);
                if (match != m_matchAllSubjectAltNames)
                    return match;
            }

            return m_matchAllSubjectAltNames;
        }

        private static bool ContainsGeneralName(GeneralName[] names, GeneralName name) =>
            Array.IndexOf(names, name) >= 0;

        private static bool MatchExtension(byte[] b, X509Certificate c, DerObjectIdentifier oid)
        {
            if (b == null)
                return true;

            Asn1OctetString extVal = c.GetExtensionValue(oid);

            if (extVal == null)
                return false;

            return Arrays.AreEqual(b, extVal.GetOctets());
        }

        private static bool PoliciesIntersect(ISet<DerObjectIdentifier> policy, Asn1Sequence certificatePolicies)
        {
            foreach (var element in certificatePolicies)
            {
                var policyInformation = PolicyInformation.GetInstance(element);
                if (policy.Contains(policyInformation.PolicyIdentifier))
                    return true;
            }
            return false;
        }
    }
}
