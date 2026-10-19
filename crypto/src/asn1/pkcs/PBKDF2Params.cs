using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The PBKDF2-params structure of PKCS#5 v2.1.</summary>
    public class Pbkdf2Params
        : Asn1Encodable
    {
        /// <summary>The default pseudo-random function, HMAC with SHA-1.</summary>
        public static readonly AlgorithmIdentifier DefaultPrf = new AlgorithmIdentifier(
            PkcsObjectIdentifiers.IdHmacWithSha1, DerNull.Instance);

        /// <summary>Return an <see cref="Pbkdf2Params"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Pbkdf2Params"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Pbkdf2Params"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="Pbkdf2Params"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Pbkdf2Params"/>.</returns>
        public static Pbkdf2Params GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Pbkdf2Params(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="Pbkdf2Params"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Pbkdf2Params"/>.</returns>
        public static Pbkdf2Params GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Pbkdf2Params(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_octStr;
        private readonly DerInteger m_iterationCount, m_keyLength;
        private readonly AlgorithmIdentifier m_prf;

        /// <summary>Create a new <see cref="Pbkdf2Params"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public Pbkdf2Params(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_octStr = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_iterationCount = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_keyLength = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_prf = Asn1Utilities.ReadOptional(seq, ref pos, AlgorithmIdentifier.GetOptional) ?? DefaultPrf;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Pbkdf2Params"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The iteration count.</param>
        public Pbkdf2Params(byte[] salt, int iterationCount)
            : this(salt, iterationCount, prf: null)
        {
        }

        /// <summary>Create a new <see cref="Pbkdf2Params"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The iteration count.</param>
        /// <param name="keyLength">The key length.</param>
        public Pbkdf2Params(byte[] salt, int iterationCount, int keyLength)
            : this(salt, iterationCount, keyLength, prf: null)
        {
        }

        /// <summary>Create a new <see cref="Pbkdf2Params"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The iteration count.</param>
        /// <param name="prf">The prf.</param>
        public Pbkdf2Params(byte[] salt, int iterationCount, AlgorithmIdentifier prf)
        {
            m_octStr = DerOctetString.FromContents(salt);
            m_iterationCount = DerInteger.ValueOf(iterationCount);
            m_keyLength = null;
            m_prf = prf ?? DefaultPrf;
        }

        /// <summary>Create a new <see cref="Pbkdf2Params"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The iteration count.</param>
        /// <param name="keyLength">The key length.</param>
        /// <param name="prf">The prf.</param>
        public Pbkdf2Params(byte[] salt, int iterationCount, int keyLength, AlgorithmIdentifier prf)
        {
            m_octStr = DerOctetString.FromContents(salt);
            m_iterationCount = DerInteger.ValueOf(iterationCount);
            m_keyLength = DerInteger.ValueOf(keyLength);
            m_prf = prf ?? DefaultPrf;
        }

        /// <summary>Return the salt.</summary>
        public byte[] GetSalt() => m_octStr.GetOctets();

        /// <summary>Gets the iteration count.</summary>
        public BigInteger IterationCount => m_iterationCount.Value;

        /// <summary>Gets the iteration count object.</summary>
        public DerInteger IterationCountObject => m_iterationCount;

        /// <summary>Gets the key length.</summary>
        public BigInteger KeyLength => m_keyLength?.Value;

        /// <summary>Gets the key length object.</summary>
        public DerInteger KeyLengthObject => m_keyLength;

        /// <summary>Gets a value indicating whether this is default prf.</summary>
        public bool IsDefaultPrf => DefaultPrf.Equals(m_prf);

        /// <summary>Gets the prf.</summary>
        public AlgorithmIdentifier Prf => m_prf;

        /// <summary>Gets the salt.</summary>
        public Asn1OctetString Salt => m_octStr;

        /// <inheritdoc/>
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
