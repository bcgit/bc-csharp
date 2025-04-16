using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public enum PkiStatus
	{
		Granted					= 0,
		GrantedWithMods			= 1,
		Rejection				= 2,
		Waiting					= 3,
		RevocationWarning		= 4,
		RevocationNotification	= 5,
    	KeyUpdateWarning		= 6,
	}

	public class PkiStatusEncodable
		: Asn1Encodable
	{
		public static readonly PkiStatusEncodable granted = new PkiStatusEncodable(PkiStatus.Granted);
		public static readonly PkiStatusEncodable grantedWithMods = new PkiStatusEncodable(PkiStatus.GrantedWithMods);
		public static readonly PkiStatusEncodable rejection = new PkiStatusEncodable(PkiStatus.Rejection);
		public static readonly PkiStatusEncodable waiting = new PkiStatusEncodable(PkiStatus.Waiting);
		public static readonly PkiStatusEncodable revocationWarning = new PkiStatusEncodable(PkiStatus.RevocationWarning);
		public static readonly PkiStatusEncodable revocationNotification = new PkiStatusEncodable(PkiStatus.RevocationNotification);
		public static readonly PkiStatusEncodable keyUpdateWaiting = new PkiStatusEncodable(PkiStatus.KeyUpdateWarning);

        public static PkiStatusEncodable GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiStatusEncodable pkiStatusEncodable)
                return pkiStatusEncodable;
            return new PkiStatusEncodable(DerInteger.GetInstance(obj));
        }

        public static PkiStatusEncodable GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiStatusEncodable(DerInteger.GetInstance(taggedObject, declaredExplicit));

        public static PkiStatusEncodable GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiStatusEncodable(DerInteger.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_status;

		private PkiStatusEncodable(PkiStatus status)
			: this(new DerInteger((int)status))
		{
		}

		private PkiStatusEncodable(DerInteger status)
		{
			m_status = status;
		}

		public virtual DerInteger Status => m_status;

		public virtual BigInteger Value => m_status.Value;

		public override Asn1Object ToAsn1Object() => m_status;
	}
}
