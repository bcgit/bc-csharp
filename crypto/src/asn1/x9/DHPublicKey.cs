using System;

namespace Org.BouncyCastle.Asn1.X9
{
    public class DHPublicKey
		: Asn1Encodable
	{
        public static DHPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DHPublicKey dhPublicKey)
                return dhPublicKey;
            return new DHPublicKey(DerInteger.GetInstance(obj));
        }

        public static DHPublicKey GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new DHPublicKey(DerInteger.GetInstance(obj, isExplicit));

        public static DHPublicKey GetTagged(Asn1TaggedObject obj, bool isExplicit) =>
            new DHPublicKey(DerInteger.GetTagged(obj, isExplicit));

        private readonly DerInteger m_y;

        public DHPublicKey(DerInteger y)
		{
			m_y = y ?? throw new ArgumentNullException(nameof(y));
        }

        public DerInteger Y => m_y;

        public override Asn1Object ToAsn1Object() => m_y;
	}
}
