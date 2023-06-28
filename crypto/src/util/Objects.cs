using System;
using System.Threading;

namespace Org.BouncyCastle.Utilities
{
    public static class Objects
    {
        public static int GetHashCode(object obj)
        {
            return null == obj ? 0 : obj.GetHashCode();
        }

        internal static TValue EnsureSingletonInitialized<TValue, TArg>(ref TValue value, TArg arg,
            Func<TArg, TValue> initialize)
            where TValue : class
        {
            TValue currentValue = Volatile.Read(ref value);
            if (null != currentValue)
                return currentValue;

            TValue candidateValue = initialize(arg);

            return Interlocked.CompareExchange(ref value, candidateValue, null) ?? candidateValue;
        }
    }
}
