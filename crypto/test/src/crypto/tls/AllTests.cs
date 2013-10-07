using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tls.Test
{
    public static class AllTests
    {
        private static ITest[] tests = new ITest[]
        {
            new DTLSProtocolTest(),
            new TLSProtocolTest(), 
        };

        public static void Main(string[] args) 
        {
            foreach (var test in tests)
            {
                var result = test.Perform();
                Console.WriteLine(result);
            }
        }
    }
}
