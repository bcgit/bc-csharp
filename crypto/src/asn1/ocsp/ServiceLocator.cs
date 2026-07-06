using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class ServiceLocator
        : Asn1Encodable
    {
        public static ServiceLocator GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ServiceLocator serviceLocator)
                return serviceLocator;
            return new ServiceLocator(Asn1Sequence.GetInstance(obj));
        }

        public static ServiceLocator GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new ServiceLocator(Asn1Sequence.GetInstance(obj, explicitly));

        public static ServiceLocator GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ServiceLocator(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly X509Name m_issuer;
        private readonly AuthorityInformationAccess m_locator;

        public ServiceLocator(X509Name issuer)
            : this(issuer, (AuthorityInformationAccess)null)
        {
        }

        [Obsolete("Use constructor from 'AuthorityInformationAccess' instead")]
        public ServiceLocator(X509Name issuer, Asn1Object locator)
            : this(issuer, AuthorityInformationAccess.GetInstance(locator))
        {
        }

        public ServiceLocator(X509Name issuer, AuthorityInformationAccess locator)
        {
            m_issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            m_locator = locator;
        }

        private ServiceLocator(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuer = Asn1Utilities.Read(seq, ref pos, X509Name.GetInstance);
            m_locator = Asn1Utilities.ReadOptional(seq, ref pos, AuthorityInformationAccess.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public X509Name Issuer => m_issuer;

        // TODO[api] Return type as AuthorityInformationAccess
        [Obsolete("Use 'LocatorValue' instead")]
        public Asn1Object Locator => m_locator?.ToAsn1Object();

        public AuthorityInformationAccess LocatorValue => m_locator;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * ServiceLocator ::= Sequence {
         *     issuer    Name,
         *     locator   AuthorityInfoAccessSyntax OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_locator == null
                ? new DerSequence(m_issuer)
                : new DerSequence(m_issuer, m_locator);
        }
    }
}
