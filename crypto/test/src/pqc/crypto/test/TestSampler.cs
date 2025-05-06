using System;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    internal class TestSampler
    {
        private readonly bool m_full;
        private readonly int m_offset;

        internal TestSampler()
        {
            // TODO: bc-java allows running exhaustive tests via property
            //m_full = Properties.isOverrideSet("test.full");
            m_full = false;

            m_offset = new Random((int)(DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond)).Next(10);
        }

        internal bool SkipTest(string count) => !m_full && ShouldSkip(int.Parse(count));

        internal bool SkipTest(int count) => !m_full && ShouldSkip(count);

        private bool ShouldSkip(int count) => count != 0 && ((count + m_offset) % 9 != 0);
    }
}
