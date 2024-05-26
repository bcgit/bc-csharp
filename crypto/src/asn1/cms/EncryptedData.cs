using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class EncryptedData
		: Asn1Encodable
	{
        public static EncryptedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedData encryptedData)
                return encryptedData;
            return new EncryptedData(Asn1Sequence.GetInstance(obj));
        }

		public static EncryptedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
            return new EncryptedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger				version;
		private readonly EncryptedContentInfo	encryptedContentInfo;
		private readonly Asn1Set				unprotectedAttrs;

		public EncryptedData(
			EncryptedContentInfo encInfo)
			: this(encInfo, null)
		{
		}

		public EncryptedData(
			EncryptedContentInfo	encInfo,
			Asn1Set					unprotectedAttrs)
		{
			if (encInfo == null)
				throw new ArgumentNullException("encInfo");

			this.version = new DerInteger((unprotectedAttrs == null) ? 0 : 2);
			this.encryptedContentInfo = encInfo;
			this.unprotectedAttrs = unprotectedAttrs;
		}

		private EncryptedData(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count < 2 || count > 3)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			int pos = 0;

			this.version = DerInteger.GetInstance(seq[pos++]);
			this.encryptedContentInfo = EncryptedContentInfo.GetInstance(seq[pos++]);
			this.unprotectedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual DerInteger Version
		{
			get { return version; }
		}

		public virtual EncryptedContentInfo EncryptedContentInfo
		{
			get { return encryptedContentInfo; }
		}

		public virtual Asn1Set UnprotectedAttrs
		{
			get { return unprotectedAttrs; }
		}

		/**
		* <pre>
		*       EncryptedData ::= SEQUENCE {
		*                     version CMSVersion,
		*                     encryptedContentInfo EncryptedContentInfo,
		*                     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
		* </pre>
		* @return a basic ASN.1 object representation.
		*/
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(version, encryptedContentInfo);

			if (unprotectedAttrs != null)
			{
				v.Add(new BerTaggedObject(false, 1, unprotectedAttrs));
			}

			return new BerSequence(v);
		}
	}
}
