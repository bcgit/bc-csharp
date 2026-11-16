using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The ServiceLocator structure of RFC 6960.</summary>
    public class ServiceLocator
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ServiceLocator"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ServiceLocator"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ServiceLocator"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ServiceLocator GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ServiceLocator serviceLocator)
                return serviceLocator;
            return new ServiceLocator(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ServiceLocator"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ServiceLocator"/>.</returns>
        public static ServiceLocator GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new ServiceLocator(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="ServiceLocator"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ServiceLocator"/>.</returns>
        public static ServiceLocator GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ServiceLocator(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly X509Name m_issuer;
        private readonly AuthorityInformationAccess m_locator;

        /// <summary>Create a new <see cref="ServiceLocator"/>.</summary>
        /// <param name="issuer">The issuer.</param>
        public ServiceLocator(X509Name issuer)
            : this(issuer, (AuthorityInformationAccess)null)
        {
        }

        /// <summary>Create a new <see cref="ServiceLocator"/>.</summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="locator">The locator.</param>
        [Obsolete("Use constructor from 'AuthorityInformationAccess' instead")]
        public ServiceLocator(X509Name issuer, Asn1Object locator)
            : this(issuer, AuthorityInformationAccess.GetInstance(locator))
        {
        }

        /// <summary>Create a new <see cref="ServiceLocator"/>.</summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="locator">The locator.</param>
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

        /// <summary>Gets the issuer.</summary>
        public X509Name Issuer => m_issuer;

        /// <summary>Gets the locator.</summary>
        // TODO[api] Return type as AuthorityInformationAccess
        [Obsolete("Use 'LocatorValue' instead")]
        public Asn1Object Locator => m_locator?.ToAsn1Object();

        /// <summary>Gets the locator value.</summary>
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
