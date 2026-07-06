using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     * Challenge ::= SEQUENCE {
     *          owf                 AlgorithmIdentifier  OPTIONAL,
     *
     *          -- MUST be present in the first Challenge; MAY be omitted in
     *          -- any subsequent Challenge in POPODecKeyChallContent (if
     *          -- omitted, then the owf used in the immediately preceding
     *          -- Challenge is to be used).
     *
     *          witness             OCTET STRING,
     *          -- the result of applying the one-way function (owf) to a
     *          -- randomly-generated INTEGER, A.  [Note that a different
     *          -- INTEGER MUST be used for each Challenge.]
     *          challenge           OCTET STRING
     *          -- the encryption (under the public key for which the cert.
     *          -- request is being made) of Rand, where Rand is specified as
     *          --   Rand ::= SEQUENCE {
     *          --      int      INTEGER,
     *          --       - the randomly-generated INTEGER A (above)
     *          --      sender   GeneralName
     *          --       - the sender's name (as included in PKIHeader)
     *          --   }
     *      }
     *      </pre>
     */
    public class Challenge
        : Asn1Encodable
    {
        public static Challenge GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Challenge challenge)
                return challenge;
            return new Challenge(Asn1Sequence.GetInstance(obj));
        }

        public static Challenge GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Challenge(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Challenge GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Challenge(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_owf;
        private readonly Asn1OctetString m_witness;
        private readonly Asn1OctetString m_challenge;

        private Challenge(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_owf = Asn1Utilities.ReadOptional(seq, ref pos, AlgorithmIdentifier.GetOptional);
            m_witness = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_challenge = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Challenge(byte[] witness, byte[] challenge)
            : this(null, witness, challenge)
        {
        }

        public Challenge(AlgorithmIdentifier owf, byte[] witness, byte[] challenge)
        {
            m_owf = owf;
            m_witness = DerOctetString.FromContents(witness);
            m_challenge = DerOctetString.FromContents(challenge);
        }

        public virtual AlgorithmIdentifier Owf => m_owf;

        public virtual Asn1OctetString Witness => m_witness;

        public virtual Asn1OctetString ChallengeValue => m_challenge;

        /**
         * <pre>
         * Challenge ::= SEQUENCE {
         *                 owf                 AlgorithmIdentifier  OPTIONAL,
         *
         *                 -- MUST be present in the first Challenge; MAY be omitted in
         *                 -- any subsequent Challenge in POPODecKeyChallContent (if
         *                 -- omitted, then the owf used in the immediately preceding
         *                 -- Challenge is to be used).
         *
         *                 witness             OCTET STRING,
         *                 -- the result of applying the one-way function (owf) to a
         *                 -- randomly-generated INTEGER, A.  [Note that a different
         *                 -- INTEGER MUST be used for each Challenge.]
         *                 challenge           OCTET STRING
         *                 -- the encryption (under the public key for which the cert.
         *                 -- request is being made) of Rand, where Rand is specified as
         *                 --   Rand ::= SEQUENCE {
         *                 --      int      INTEGER,
         *                 --       - the randomly-generated INTEGER A (above)
         *                 --      sender   GeneralName
         *                 --       - the sender's name (as included in PKIHeader)
         *                 --   }
         *      }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptional(m_owf);
            v.Add(m_witness, m_challenge);
            return new DerSequence(v);
        }

        /// <summary>Rand is the inner type.</summary>
        // TODO[api] Make static
        public class Rand
            : Asn1Encodable
        {
            public static Rand GetInstance(object obj)
            {
                if (obj == null)
                    return null;
                if (obj is Rand rand)
                    return rand;
#pragma warning disable CS0618 // Type or member is obsolete
                return new Rand(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
            }

            public static Rand GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
#pragma warning disable CS0618 // Type or member is obsolete
                new Rand(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete

            public static Rand GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
#pragma warning disable CS0618 // Type or member is obsolete
                new Rand(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete

            private readonly DerInteger m_intVal;
            private readonly GeneralName m_sender;

            public Rand(DerInteger intVal, GeneralName sender)
            {
                m_intVal = intVal ?? throw new ArgumentNullException(nameof(intVal));
                m_sender = sender ?? throw new ArgumentNullException(nameof(sender));
            }

            [Obsolete("Use 'GetInstance' instead")]
            public Rand(Asn1Sequence seq)
            {
                if (seq == null)
                    throw new ArgumentNullException(nameof(seq));

                int count = seq.Count, pos = 0;
                if (count != 2)
                    throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

                m_intVal = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
                m_sender = Asn1Utilities.Read(seq, ref pos, GeneralName.GetInstance);

                if (pos != count)
                    throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
            }

            public virtual DerInteger IntVal => m_intVal;

            public virtual GeneralName Sender => m_sender;

            public override Asn1Object ToAsn1Object() => new DerSequence(m_intVal, m_sender);
        }
    }
}
