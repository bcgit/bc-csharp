using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class ResponderID
        : Asn1Encodable, IAsn1Choice
    {
		public static ResponderID GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is ResponderID responderID)
				return responderID;

			if (obj is Asn1OctetString asn1OctetString)
				return new ResponderID(asn1OctetString);

			if (obj is Asn1TaggedObject taggedObject)
			{
				if (taggedObject.HasContextTag(1))
					return new ResponderID(X509Name.GetInstance(taggedObject, true));

				return new ResponderID(Asn1OctetString.GetInstance(taggedObject, true));
			}

			return new ResponderID(X509Name.GetInstance(obj));
		}

        public static ResponderID GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

        public static ResponderID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

        public ResponderID(Asn1OctetString id)
        {
			m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

		public ResponderID(X509Name id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

		public virtual byte[] GetKeyHash()
		{
			if (m_id is Asn1OctetString asn1OctetString)
				return asn1OctetString.GetOctets();

			return null;
		}

		public virtual X509Name Name
		{
			get
			{
				if (m_id is Asn1OctetString)
					return null;

				return X509Name.GetInstance(m_id);
			}
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * ResponderID ::= CHOICE {
         *      byName          [1] Name,
         *      byKey           [2] KeyHash }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_id is Asn1OctetString asn1OctetString)
                return new DerTaggedObject(true, 2, asn1OctetString);

			return new DerTaggedObject(true, 1, m_id);
        }
    }
}
