using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;

namespace Org.BouncyCastle.Tsp
{
    public class GenTimeAccuracy
    {
        private readonly Accuracy m_accuracy;

        public GenTimeAccuracy(Accuracy accuracy)
        {
            m_accuracy = accuracy;
        }

        public int Seconds => GetTimeComponent(m_accuracy.Seconds);

        public int Millis => GetTimeComponent(m_accuracy.Millis);

        public int Micros => GetTimeComponent(m_accuracy.Micros);

        public override string ToString() => Seconds + "." + Millis.ToString("000") + Micros.ToString("000");

        private static int GetTimeComponent(DerInteger time) => time == null ? 0 : time.IntValueExact;
    }
}
