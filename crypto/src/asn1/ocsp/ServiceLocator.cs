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

        public static ServiceLocator GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new ServiceLocator(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly X509Name m_issuer;
        private readonly Asn1Object m_locator;

        public ServiceLocator(X509Name issuer)
            : this(issuer, null)
        {
        }

        public ServiceLocator(X509Name issuer, Asn1Object locator)
        {
			m_issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
			m_locator = locator;
		}

        private ServiceLocator(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_issuer = X509Name.GetInstance(seq[pos++]);

            if (pos < count)
            {
                m_locator = seq[pos++].ToAsn1Object();
            }

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public X509Name Issuer => m_issuer;

        public Asn1Object Locator => m_locator;

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
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_issuer);
            v.AddOptional(m_locator);
            return new DerSequence(v);
        }
    }
}
