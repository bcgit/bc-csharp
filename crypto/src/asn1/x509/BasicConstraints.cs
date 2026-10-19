using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The BasicConstraints extension of RFC 5280.</summary>
    public class BasicConstraints
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="BasicConstraints"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="BasicConstraints"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="BasicConstraints"/>, or null if <paramref name="obj"/> is null.</returns>
        public static BasicConstraints GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BasicConstraints basicConstraints)
                return basicConstraints;
            // TODO[api] Remove this case
            if (obj is X509Extension x509Extension)
                return GetInstance(X509Extension.ConvertValueToObject(x509Extension));
            return new BasicConstraints(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="BasicConstraints"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BasicConstraints"/>.</returns>
        public static BasicConstraints GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new BasicConstraints(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="BasicConstraints"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BasicConstraints"/>.</returns>
        public static BasicConstraints GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BasicConstraints(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static BasicConstraints FromExtensions(X509Extensions extensions)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.BasicConstraints));
        }

        private readonly DerBoolean m_cA;
        private readonly DerInteger m_pathLenConstraint;

        private BasicConstraints(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_cA = Asn1Utilities.ReadOptional(seq, ref pos, DerBoolean.GetOptional) ?? DerBoolean.False;
            m_pathLenConstraint = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="BasicConstraints"/>.</summary>
        /// <param name="cA">true if c a, false otherwise.</param>
        public BasicConstraints(bool cA)
        {
            m_cA = cA ? DerBoolean.True : DerBoolean.False;
            m_pathLenConstraint = null;
        }

        /**
         * create a cA=true object for the given path length constraint.
         *
         * @param pathLenConstraint
         */
        public BasicConstraints(int pathLenConstraint)
        {
            m_cA = DerBoolean.True;
            m_pathLenConstraint = DerInteger.ValueOf(pathLenConstraint);
        }

        public bool IsCA() => m_cA.IsTrue;

        /// <summary>Gets the path len constraint.</summary>
        public BigInteger PathLenConstraint => m_pathLenConstraint?.Value;

        /// <summary>Gets the path len constraint integer.</summary>
        public DerInteger PathLenConstraintInteger => m_pathLenConstraint;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * BasicConstraints := Sequence {
         *    cA                  Boolean DEFAULT FALSE,
         *    pathLenConstraint   Integer (0..MAX) OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            if (m_cA.IsTrue)
            {
                v.Add(m_cA);
            }
            v.AddOptional(m_pathLenConstraint); // yes some people actually do this when cA is false...
            return new DerSequence(v);
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            if (m_pathLenConstraint == null)
                return "BasicConstraints: isCa(" + IsCA() + ")";

            return "BasicConstraints: isCa(" + IsCA() + "), pathLenConstraint = " + m_pathLenConstraint.Value;
        }
    }
}
