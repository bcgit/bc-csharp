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

        /// <summary>
        /// Publish <paramref name="candidateValue"/> into <paramref name="value"/> if nothing is there yet, and return
        /// whichever ends up published.
        /// </summary>
        /// <remarks>
        /// For a value computed before it is known whether another thread got there first: the first to publish
        /// wins and every caller adopts that one instance, so a value shared by reference is shared from a single
        /// copy. <see cref="EnsureSingletonInitialized{TValue, TArg}"/> is the form for a value not yet computed.
        /// </remarks>
        internal static TValue EnsureSingletonInitialized<TValue>(ref TValue value, TValue candidateValue)
            where TValue : class
        {
            TValue currentValue = Volatile.Read(ref value);
            if (null != currentValue)
                return currentValue;

            return Interlocked.CompareExchange(ref value, candidateValue, null) ?? candidateValue;
        }

        /// <summary>
        /// Return the value in <paramref name="value"/>, computing and publishing it with
        /// <paramref name="initialize"/> if nothing is there yet.
        /// </summary>
        /// <remarks>
        /// Lock-free lazy initialization for a value that is a pure function of <paramref name="arg"/>: racing
        /// callers may each run <paramref name="initialize"/>, the first to publish wins, and every caller returns
        /// that one instance, so the work is wasted at worst and never observed. <paramref name="initialize"/>
        /// must therefore be safe to run more than once and free of side effects other than its result.
        /// <paramref name="arg"/> exists so that a static method or cached delegate can be passed in place of a
        /// closure, which would allocate on every call.
        /// </remarks>
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
