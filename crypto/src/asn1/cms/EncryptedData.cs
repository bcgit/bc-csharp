using System;

namespace Org.BouncyCastle.Asn1.Cms
{
	public class EncryptedData
		: Asn1Encodable
	{
		private readonly DerInteger				version;
		private readonly EncryptedContentInfo	encryptedContentInfo;
		private readonly Asn1Sequence				unprotectedAttrs;

		public static EncryptedData GetInstance(
			object obj)
		{
			if (obj is EncryptedData)
				return (EncryptedData) obj;

			if (obj is Asn1Sequence)
				return new EncryptedData((Asn1Sequence) obj);

			throw new ArgumentException("Invalid EncryptedData: " + obj.GetType().Name);
		}

		public EncryptedData(
			EncryptedContentInfo encInfo)
			: this(encInfo, null)
		{
		}

		public EncryptedData(
			EncryptedContentInfo	encInfo,
			Asn1Sequence			unprotectedAttrs)
		{
			if (encInfo == null)
				throw new ArgumentNullException("encInfo");

			this.version = new DerInteger((unprotectedAttrs == null) ? 0 : 2);
			this.encryptedContentInfo = encInfo;
			this.unprotectedAttrs = unprotectedAttrs;
		}

		private EncryptedData(
			Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException("seq");
			if (seq.Count < 2 || seq.Count > 3)
				throw new ArgumentException("Bad sequence size: " + seq.Count, "seq");

			this.version = DerInteger.GetInstance(seq[0]);
			this.encryptedContentInfo = EncryptedContentInfo.GetInstance(seq[1]);

			if (seq.Count > 2)
			{
                var taggedObj = seq[2] as Asn1TaggedObject;
                if (taggedObj == null) {
                    throw new ArgumentException("Bad unprotected attributes");
                }
				this.unprotectedAttrs = Asn1Sequence.GetInstance(taggedObj.GetObject());
			}
		}

		public virtual DerInteger Version
		{
			get { return version; }
		}

		public virtual EncryptedContentInfo EncryptedContentInfo
		{
			get { return encryptedContentInfo; }
		}

		public virtual Asn1Sequence UnprotectedAttrs
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
