using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The CRLNumber object.
     * <pre>
     * CRLNumber::= Integer(0..MAX)
     * </pre>
     */
    public class CrlNumber
        : DerInteger
    {
        /// <summary>Create a new <see cref="CrlNumber"/>.</summary>
        /// <param name="number">The number.</param>
        public CrlNumber(
            BigInteger number)
            : base(number)
        {
        }

        /// <summary>Gets the number.</summary>
        public BigInteger Number
        {
            get { return PositiveValue; }
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return "CRLNumber: " + Number;
        }
    }
}
