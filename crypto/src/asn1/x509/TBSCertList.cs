using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    public class CrlEntry
		: Asn1Encodable
	{
		public static CrlEntry GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is CrlEntry crlEntry)
				return crlEntry;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlEntry(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static CrlEntry GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlEntry(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static CrlEntry GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlEntry(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Sequence m_seq;

        private readonly DerInteger m_userCertificate;
        private readonly Time m_revocationDate;
        private readonly X509Extensions m_crlEntryExtensions;

        [Obsolete("Use 'GetInstance' instead")]
        public CrlEntry(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_userCertificate = DerInteger.GetInstance(seq[pos++]);
            m_revocationDate = Time.GetInstance(seq[pos++]);
            m_crlEntryExtensions = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

			m_seq = seq;
		}

        public DerInteger UserCertificate => m_userCertificate;

        public Time RevocationDate => m_revocationDate;

        public X509Extensions Extensions => m_crlEntryExtensions;

        public override Asn1Object ToAsn1Object() => m_seq;
	}

	/**
     * PKIX RFC-2459 - TbsCertList object.
     * <pre>
     * TbsCertList  ::=  Sequence  {
     *      version                 Version OPTIONAL,
     *                                   -- if present, shall be v2
     *      signature               AlgorithmIdentifier,
     *      issuer                  Name,
     *      thisUpdate              Time,
     *      nextUpdate              Time OPTIONAL,
     *      revokedCertificates     Sequence OF Sequence  {
     *           userCertificate         CertificateSerialNumber,
     *           revocationDate          Time,
     *           crlEntryExtensions      Extensions OPTIONAL
     *                                         -- if present, shall be v2
     *                                }  OPTIONAL,
     *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
     *                                         -- if present, shall be v2
     *                                }
     * </pre>
     */
    public class TbsCertificateList
        : Asn1Encodable
    {
		private class RevokedCertificatesEnumeration
			: IEnumerable<CrlEntry>
		{
			private readonly IEnumerable<Asn1Encodable> m_en;

			internal RevokedCertificatesEnumeration(IEnumerable<Asn1Encodable> en)
			{
				m_en = en;
			}

			System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

			public IEnumerator<CrlEntry> GetEnumerator() => new RevokedCertificatesEnumerator(m_en.GetEnumerator());

			private sealed class RevokedCertificatesEnumerator
				: IEnumerator<CrlEntry>
			{
				private readonly IEnumerator<Asn1Encodable> m_e;

				internal RevokedCertificatesEnumerator(IEnumerator<Asn1Encodable> e)
				{
					m_e = e;
				}

				public void Dispose()
				{
					m_e.Dispose();
                    GC.SuppressFinalize(this);
                }

                public bool MoveNext() => m_e.MoveNext();

				public void Reset() => m_e.Reset();

				object System.Collections.IEnumerator.Current => Current;

				public CrlEntry Current => CrlEntry.GetInstance(m_e.Current);
			}
		}

		public static TbsCertificateList GetInstance(object obj)
        {
			if (obj == null)
				return null;
			if (obj is TbsCertificateList tbsCertificateList)
				return tbsCertificateList;
			return new TbsCertificateList(Asn1Sequence.GetInstance(obj));
        }

        public static TbsCertificateList GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new TbsCertificateList(Asn1Sequence.GetInstance(obj, explicitly));

        public static TbsCertificateList GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TbsCertificateList(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_seq;

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_signature;
        private readonly X509Name m_issuer;
        private readonly Time m_thisUpdate;
        private readonly Time m_nextUpdate;
        private readonly Asn1Sequence m_revokedCertificates;
        private readonly X509Extensions m_crlExtensions;

        private TbsCertificateList(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // TODO[api] This field is not actually declared with a DEFAULT
            m_version = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional) ?? DerInteger.Zero;
            m_signature = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_issuer = X509Name.GetInstance(seq[pos++]);
            m_thisUpdate = Time.GetInstance(seq[pos++]);
            m_nextUpdate = Asn1Utilities.ReadOptional(seq, ref pos, Time.GetOptional);
            m_revokedCertificates = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);
            m_crlExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_seq = seq;
        }

		public int Version => m_version.IntValueExact + 1;

        public DerInteger VersionNumber => m_version;

        public AlgorithmIdentifier Signature => m_signature;

        public X509Name Issuer => m_issuer;

        public Time ThisUpdate => m_thisUpdate;

        public Time NextUpdate => m_nextUpdate;

        // TODO[api] Don't convert null to empty array
		public CrlEntry[] GetRevokedCertificates() =>
            m_revokedCertificates?.MapElements(CrlEntry.GetInstance) ?? Array.Empty<CrlEntry>();

		public IEnumerable<CrlEntry> GetRevokedCertificateEnumeration()
		{
			if (m_revokedCertificates == null)
				return new List<CrlEntry>(0);

			return new RevokedCertificatesEnumeration(m_revokedCertificates);
		}

		public X509Extensions Extensions => m_crlExtensions;

		public override Asn1Object ToAsn1Object() => m_seq;
    }
}
