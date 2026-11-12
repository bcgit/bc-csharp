using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>The accuracy of the time in a time-stamp token, as seconds, milliseconds and microseconds.</summary>
    /// <remarks>Components that are absent from the token's accuracy are reported as zero.</remarks>
    public class GenTimeAccuracy
    {
        private readonly Accuracy m_accuracy;

        /// <summary>Create from an ASN.1 Accuracy structure.</summary>
        /// <param name="accuracy">The ASN.1 structure.</param>
        /// <exception cref="ArgumentNullException"><paramref name="accuracy"/> is null.</exception>
        public GenTimeAccuracy(Accuracy accuracy)
        {
            m_accuracy = accuracy ?? throw new ArgumentNullException(nameof(accuracy));
        }

        /// <summary>Gets the seconds component of the accuracy.</summary>
        public int Seconds => GetTimeComponent(m_accuracy.Seconds);

        /// <summary>Gets the milliseconds component of the accuracy.</summary>
        public int Millis => GetTimeComponent(m_accuracy.Millis);

        /// <summary>Gets the microseconds component of the accuracy.</summary>
        public int Micros => GetTimeComponent(m_accuracy.Micros);

        /// <summary>Format the accuracy as seconds, a point, then three digits each of millis and micros.</summary>
        public override string ToString() => Seconds + "." + Millis.ToString("000") + Micros.ToString("000");

        private static int GetTimeComponent(DerInteger time) => time?.IntValueExact ?? 0;
    }
}
