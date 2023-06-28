using System;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    internal class TestSampler
    {
        private readonly bool isFull;
        private readonly int offSet;

        internal TestSampler()
        {
            this.isFull = false;
            this.offSet = new Random().Next() % 10;
        }

        internal bool SkipTest(string count)
        {
            if (isFull)
                return false;

            int c = int.Parse(count);
            return c != 0 && ((c + offSet) % 9 != 0);
        }
    }
}
