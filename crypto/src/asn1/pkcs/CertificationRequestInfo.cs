using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     * Pkcs10 CertificationRequestInfo object.
     * <pre>
     *  CertificationRequestInfo ::= Sequence {
     *   version             Integer { v1(0) } (v1,...),
     *   subject             Name,
     *   subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
     *   attributes          [0] Attributes{{ CRIAttributes }}
     *  }
     *
     *  Attributes { ATTRIBUTE:IOSet } ::= Set OF Attr{{ IOSet }}
     *
     *  Attr { ATTRIBUTE:IOSet } ::= Sequence {
     *    type    ATTRIBUTE.&amp;id({IOSet}),
     *    values  Set SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
     *  }
     * </pre>
     */
    public class CertificationRequestInfo
        : Asn1Encodable
    {
		public static CertificationRequestInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificationRequestInfo certificationRequestInfo)
                return certificationRequestInfo;
            return new CertificationRequestInfo(Asn1Sequence.GetInstance(obj));
		}

        public static CertificationRequestInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CertificationRequestInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_version;
        private readonly X509Name m_subject;
        private readonly SubjectPublicKeyInfo m_subjectPKInfo;
        private readonly Asn1Set m_attributes;

        public CertificationRequestInfo(X509Name subject, SubjectPublicKeyInfo pkInfo, Asn1Set attributes)
        {
            m_version = DerInteger.Zero;
            m_subject = subject ?? throw new ArgumentNullException(nameof(subject));
            m_subjectPKInfo = pkInfo ?? throw new ArgumentNullException(nameof(pkInfo));
            m_attributes = ValidateAttributes(attributes);
        }

		private CertificationRequestInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_subject = X509Name.GetInstance(seq[pos++]);
            m_subjectPKInfo = SubjectPublicKeyInfo.GetInstance(seq[pos++]);

            // NOTE: some CertificationRequestInfo objects seem to treat this field as optional.
            m_attributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            ValidateAttributes(m_attributes);
        }

        public DerInteger Version => m_version;

        public X509Name Subject => m_subject;

        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_subjectPKInfo;

        public Asn1Set Attributes => m_attributes;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_version, m_subject, m_subjectPKInfo);
            v.AddOptionalTagged(false, 0, m_attributes);
            return new DerSequence(v);
        }

        private static Asn1Set ValidateAttributes(Asn1Set attributes)
        {
            if (attributes != null)
            {
                foreach (var element in attributes)
                {
                    AttributePkcs attr = AttributePkcs.GetInstance(element);
                    if (PkcsObjectIdentifiers.Pkcs9AtChallengePassword.Equals(attr.AttrType))
                    {
                        if (attr.AttrValues.Count != 1)
                            throw new ArgumentException("challengePassword attribute must have one value");
                    }
                }
            }
            return attributes;
        }
    }
}
