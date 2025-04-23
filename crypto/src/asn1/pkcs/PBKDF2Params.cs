using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class Pbkdf2Params
        : Asn1Encodable
    {
        public static readonly AlgorithmIdentifier DefaultPrf = new AlgorithmIdentifier(
            PkcsObjectIdentifiers.IdHmacWithSha1, DerNull.Instance);

        public static Pbkdf2Params GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Pbkdf2Params pbkdf2Params)
                return pbkdf2Params;
#pragma warning disable CS0618 // Type or member is obsolete
            return new Pbkdf2Params(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static Pbkdf2Params GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Pbkdf2Params(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static Pbkdf2Params GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Pbkdf2Params(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_octStr;
        private readonly DerInteger m_iterationCount, m_keyLength;
        private readonly AlgorithmIdentifier m_prf;

        [Obsolete("Use 'GetInstance' instead")]
        public Pbkdf2Params(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_octStr = Asn1OctetString.GetInstance(seq[pos++]);
            m_iterationCount = DerInteger.GetInstance(seq[pos++]);
            m_keyLength = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_prf = Asn1Utilities.ReadOptional(seq, ref pos, AlgorithmIdentifier.GetOptional) ?? DefaultPrf;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Pbkdf2Params(byte[] salt, int iterationCount)
            : this(salt, iterationCount, prf: null)
        {
        }

        public Pbkdf2Params(byte[] salt, int iterationCount, int keyLength)
            : this(salt, iterationCount, keyLength, prf: null)
        {
        }

        public Pbkdf2Params(byte[] salt, int iterationCount, AlgorithmIdentifier prf)
        {
            m_octStr = DerOctetString.FromContents(salt);
            m_iterationCount = new DerInteger(iterationCount);
            m_keyLength = null;
            m_prf = prf ?? DefaultPrf;
        }

        public Pbkdf2Params(byte[] salt, int iterationCount, int keyLength, AlgorithmIdentifier prf)
        {
            m_octStr = DerOctetString.FromContents(salt);
            m_iterationCount = new DerInteger(iterationCount);
            m_keyLength = new DerInteger(keyLength);
            m_prf = prf ?? DefaultPrf;
        }

        public byte[] GetSalt() => m_octStr.GetOctets();

        public BigInteger IterationCount => m_iterationCount.Value;

        public DerInteger IterationCountObject => m_iterationCount;

        public BigInteger KeyLength => m_keyLength?.Value;

        public DerInteger KeyLengthObject => m_keyLength;

        public bool IsDefaultPrf => DefaultPrf.Equals(m_prf);

        public AlgorithmIdentifier Prf => m_prf;

        public Asn1OctetString Salt => m_octStr;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_octStr, m_iterationCount);
            v.AddOptional(m_keyLength);

            if (!IsDefaultPrf)
            {
                v.Add(m_prf);
            }

            return new DerSequence(v);
        }
    }
}
