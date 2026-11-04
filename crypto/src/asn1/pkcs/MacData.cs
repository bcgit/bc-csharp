using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The MacData structure of PKCS#12.</summary>
    public class MacData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="MacData"/> from the given object.</summary>
        /// <param name="obj">An <see cref="MacData"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="MacData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static MacData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MacData macData)
                return macData;
            return new MacData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="MacData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MacData"/>.</returns>
        public static MacData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MacData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="MacData"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="MacData"/>, or null if <paramref name="element"/> is null.</returns>
        public static MacData GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is MacData macData)
                return macData;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new MacData(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="MacData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MacData"/>.</returns>
        public static MacData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MacData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DigestInfo m_mac;
        private readonly Asn1OctetString m_macSalt;
        private readonly DerInteger m_iterations;

        private MacData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_mac = Asn1Utilities.Read(seq, ref pos, DigestInfo.GetInstance);
            m_macSalt = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_iterations = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional) ?? DerInteger.One;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="MacData"/>.</summary>
        /// <param name="digInfo">The dig info.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The iteration count.</param>
        // TODO[api] Fix parameter names
        public MacData(DigestInfo digInfo, byte[] salt, int iterationCount)
        {
            m_mac = digInfo ?? throw new ArgumentNullException(nameof(digInfo));
            m_macSalt = DerOctetString.FromContents(salt);
            m_iterations = DerInteger.ValueOf(iterationCount);
        }

        /// <summary>Create a new <see cref="MacData"/>.</summary>
        /// <param name="mac">The MAC.</param>
        /// <param name="macSalt">The mac salt.</param>
        /// <param name="iterations">The iterations.</param>
        public MacData(DigestInfo mac, Asn1OctetString macSalt, DerInteger iterations)
        {
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
            m_macSalt = macSalt ?? throw new ArgumentNullException(nameof(macSalt));
            m_iterations = iterations ?? throw new ArgumentNullException(nameof(iterations));
        }

        /// <summary>Gets the mac.</summary>
        public DigestInfo Mac => m_mac;

        /// <summary>Return the salt.</summary>
        public byte[] GetSalt() => (byte[])m_macSalt.GetOctets().Clone();

        /// <summary>Gets the iteration count.</summary>
        public BigInteger IterationCount => m_iterations.Value;

        /// <summary>Gets the iterations.</summary>
        public DerInteger Iterations => m_iterations;

        /// <summary>Gets the mac salt.</summary>
        public Asn1OctetString MacSalt => m_macSalt;

        /**
         * <pre>
         * MacData ::= SEQUENCE {
         *     mac      DigestInfo,
         *     macSalt  OCTET STRING,
         *     iterations INTEGER DEFAULT 1
         *     -- Note: The default is for historic reasons and its use is deprecated. A
         *     -- higher value, like 1024 is recommended.
         * </pre>
         * @return the basic DERObject construction.
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_iterations.HasValue(1)
                ?  new DerSequence(m_mac, m_macSalt)
                :  new DerSequence(m_mac, m_macSalt, m_iterations);
        }
    }
}
