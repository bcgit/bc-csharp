using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  PBMParameter ::= SEQUENCE {
     *          salt                OCTET STRING,
     *          -- note:  implementations MAY wish to limit acceptable sizes
     *          -- of this string to values appropriate for their environment
     *          -- in order to reduce the risk of denial-of-service attacks
     *          owf                 AlgorithmIdentifier,
     *          -- AlgId for a One-Way Function (SHA-1 recommended)
     *          iterationCount      INTEGER,
     *          -- number of times the OWF is applied
     *          -- note:  implementations MAY wish to limit acceptable sizes
     *          -- of this integer to values appropriate for their environment
     *          -- in order to reduce the risk of denial-of-service attacks
     *          mac                 AlgorithmIdentifier
     *          -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     *      }   -- or HMAC [RFC2104, RFC2202])
     */
    public class PbmParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PbmParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PbmParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PbmParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PbmParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbmParameter pbmParameter)
                return pbmParameter;
            return new PbmParameter(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PbmParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbmParameter"/>.</returns>
        public static PbmParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbmParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PbmParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbmParameter"/>.</returns>
        public static PbmParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbmParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_salt;
        private readonly AlgorithmIdentifier m_owf;
        private readonly DerInteger m_iterationCount;
        private readonly AlgorithmIdentifier m_mac;

        private PbmParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_salt = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_owf = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_iterationCount = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_mac = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="PbmParameter"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="owf">The owf.</param>
        /// <param name="iterationCount">The iteration count.</param>
        /// <param name="mac">The MAC.</param>
        public PbmParameter(byte[] salt, AlgorithmIdentifier owf, int iterationCount, AlgorithmIdentifier mac)
            : this(DerOctetString.FromContents(salt), owf, DerInteger.ValueOf(iterationCount), mac)
        {
        }

        /// <summary>Create a new <see cref="PbmParameter"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="owf">The owf.</param>
        /// <param name="iterationCount">The iteration count.</param>
        /// <param name="mac">The MAC.</param>
        public PbmParameter(Asn1OctetString salt, AlgorithmIdentifier owf, DerInteger iterationCount,
            AlgorithmIdentifier mac)
        {
            m_salt = salt ?? throw new ArgumentNullException(nameof(salt));
            m_owf = owf ?? throw new ArgumentNullException(nameof(owf));
            m_iterationCount = iterationCount ?? throw new ArgumentNullException(nameof(iterationCount));
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        /// <summary>Gets the iteration count.</summary>
        public virtual DerInteger IterationCount => m_iterationCount;

        /// <summary>Gets the mac.</summary>
        public virtual AlgorithmIdentifier Mac => m_mac;

        /// <summary>Gets the owf.</summary>
        public virtual AlgorithmIdentifier Owf => m_owf;

        /// <summary>Gets the salt.</summary>
        public virtual Asn1OctetString Salt => m_salt;

        /**
         * <pre>
         *  PbmParameter ::= SEQUENCE {
         *                        salt                OCTET STRING,
         *                        -- note:  implementations MAY wish to limit acceptable sizes
         *                        -- of this string to values appropriate for their environment
         *                        -- in order to reduce the risk of denial-of-service attacks
         *                        owf                 AlgorithmIdentifier,
         *                        -- AlgId for a One-Way Function (SHA-1 recommended)
         *                        iterationCount      INTEGER,
         *                        -- number of times the OWF is applied
         *                        -- note:  implementations MAY wish to limit acceptable sizes
         *                        -- of this integer to values appropriate for their environment
         *                        -- in order to reduce the risk of denial-of-service attacks
         *                        mac                 AlgorithmIdentifier
         *                        -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
         *    }   -- or HMAC [RFC2104, RFC2202])
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_salt, m_owf, m_iterationCount, m_mac);
    }
}
