using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
	/// <remarks>
	/// <pre>
	/// PrivateKeyUsagePeriod ::= SEQUENCE
	/// {
	/// notBefore       [0]     GeneralizedTime OPTIONAL,
	/// notAfter        [1]     GeneralizedTime OPTIONAL }
	/// </pre>
	/// </remarks>
	public class PrivateKeyUsagePeriod
		: Asn1Encodable
	{
		public static PrivateKeyUsagePeriod GetInstance(
			object obj)
		{
			if (obj is PrivateKeyUsagePeriod)
			{
				return (PrivateKeyUsagePeriod) obj;
			}

			if (obj is Asn1Sequence)
			{
				return new PrivateKeyUsagePeriod((Asn1Sequence) obj);
			}

			if (obj is X509Extension)
			{
				return GetInstance(X509Extension.ConvertValueToObject((X509Extension) obj));
			}

			throw new ArgumentException("unknown object in GetInstance: " + Platform.GetTypeName(obj), "obj");
		}

		private Asn1GeneralizedTime _notBefore, _notAfter;

		private PrivateKeyUsagePeriod(
			Asn1Sequence seq)
		{
			foreach (Asn1TaggedObject tObj in seq)
			{
				if (tObj.TagNo == 0)
				{
					_notBefore = Asn1GeneralizedTime.GetInstance(tObj, false);
				}
				else if (tObj.TagNo == 1)
				{
					_notAfter = Asn1GeneralizedTime.GetInstance(tObj, false);
				}
			}
		}

		public Asn1GeneralizedTime NotBefore
		{
			get { return _notBefore; }
		}

		public Asn1GeneralizedTime NotAfter
		{
			get { return _notAfter; }
		}

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, _notBefore);
            v.AddOptionalTagged(false, 1, _notAfter);
            return new DerSequence(v);
        }
	}
}
