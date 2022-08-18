using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
            int c = int.Parse(count);
            return !isFull && c != 0 && ((c + offSet) % 9 != 0);
        }
    }
}
