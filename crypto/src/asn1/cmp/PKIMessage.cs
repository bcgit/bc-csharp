using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class PkiMessage
        : Asn1Encodable
    {
        public static PkiMessage GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiMessage pkiMessage)
                return pkiMessage;
            return new PkiMessage(Asn1Sequence.GetInstance(obj));
        }

        public static PkiMessage GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly PkiHeader header;
        private readonly PkiBody body;
        private readonly DerBitString protection;
        private readonly Asn1Sequence extraCerts;

        private PkiMessage(Asn1Sequence seq)
        {
            header = PkiHeader.GetInstance(seq[0]);
            body = PkiBody.GetInstance(seq[1]);

            for (int pos = 2; pos < seq.Count; ++pos)
            {
                Asn1TaggedObject tObj = Asn1TaggedObject.GetInstance(seq[pos]);

                if (tObj.HasContextTag(0))
                {
                    protection = DerBitString.GetInstance(tObj, true);
                }
                else if (tObj.HasContextTag(1))
                {
                    extraCerts = Asn1Sequence.GetInstance(tObj, true);
                }
            }
        }

        /**
         * Creates a new PkiMessage.
         *
         * @param header message header
         * @param body message body
         * @param protection message protection (may be null)
         * @param extraCerts extra certificates (may be null)
         */
        public PkiMessage(
            PkiHeader header,
            PkiBody body,
            DerBitString protection,
            CmpCertificate[] extraCerts)
        {
            this.header = header;
            this.body = body;
            this.protection = protection;
            if (extraCerts != null)
            {
                this.extraCerts = new DerSequence(extraCerts);
            }
        }

        public PkiMessage(
            PkiHeader header,
            PkiBody body,
            DerBitString protection)
            : this(header, body, protection, null)
        {
        }

        public PkiMessage(
            PkiHeader header,
            PkiBody body)
            : this(header, body, null, null)
        {
        }

        public virtual PkiHeader Header
        {
            get { return header; }
        }

        public virtual PkiBody Body
        {
            get { return body; }
        }

        public virtual DerBitString Protection
        {
            get { return protection; }
        }

        public virtual CmpCertificate[] GetExtraCerts()
        {
            return extraCerts?.MapElements(CmpCertificate.GetInstance);
        }

        /**
         * <pre>
         * PkiMessage ::= SEQUENCE {
         *                  header           PKIHeader,
         *                  body             PKIBody,
         *                  protection   [0] PKIProtection OPTIONAL,
         *                  extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
         *                                                                     OPTIONAL
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(header, body);
            v.AddOptionalTagged(true, 0, protection);
            v.AddOptionalTagged(true, 1, extraCerts);
            return new DerSequence(v);
        }
    }
}
