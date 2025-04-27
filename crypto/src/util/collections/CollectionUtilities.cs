using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Utilities.Collections
{
    // TODO[api] Make static
    public abstract class CollectionUtilities
    {
        public static void CollectMatches<T>(ICollection<T> matches, ISelector<T> selector,
            IEnumerable<IStore<T>> stores)
        {
            if (matches == null)
                throw new ArgumentNullException(nameof(matches));
            if (stores == null)
                return;

            foreach (var store in stores)
            {
                if (store == null)
                    continue;

                foreach (T match in store.EnumerateMatches(selector))
                {
                    matches.Add(match);
                }
            }
        }

        public static IStore<T> CreateStore<T>(IEnumerable<T> contents)
        {
            return new StoreImpl<T>(contents);
        }

        public static T GetFirstOrNull<T>(IEnumerable<T> e)
            where T : class
        {
            if (e != null)
            {
                foreach (var t in e)
                {
                    return t;
                }
            }
            return null;
        }

        public static T GetValueOrKey<T>(IDictionary<T, T> d, T k)
        {
            return d.TryGetValue(k, out var v) ? v : k;
        }

        public static V GetValueOrNull<K, V>(IDictionary<K, V> d, K k)
            where V : class
        {
            return d.TryGetValue(k, out var v) ? v : null;
        }

        public static bool IsNullOrEmpty<T>(ICollection<T> c)
        {
            return c == null || c.Count < 1;
        }

        public static TResult[] Map<T, TResult>(T[] ts, Func<T, TResult> f)
        {
            int count = ts.Length;
            var result = new TResult[count];
            for (int i = 0; i < count; ++i)
            {
                result[i] = f(ts[i]);
            }
            return result;
        }

        public static IEnumerable<T> Proxy<T>(IEnumerable<T> e)
        {
            return new EnumerableProxy<T>(e);
        }

        public static ICollection<T> ReadOnly<T>(ICollection<T> c)
        {
            return new ReadOnlyCollectionProxy<T>(c);
        }

        public static IDictionary<K, V> ReadOnly<K, V>(IDictionary<K, V> d)
        {
            return new ReadOnlyDictionaryProxy<K, V>(d);
        }

        public static IList<T> ReadOnly<T>(IList<T> l)
        {
            return new ReadOnlyListProxy<T>(l);
        }

#if NETCOREAPP1_0_OR_GREATER || NET40_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        public static ISet<T> ReadOnly<T>(ISet<T> s)
        {
            return new ReadOnlySetProxy<T>(s);
        }
#endif

        public static bool Remove<K, V>(IDictionary<K, V> d, K k, out V v)
        {
            if (!d.TryGetValue(k, out v))
                return false;

            if (!d.Remove(k))
                throw new InvalidOperationException();

            return true;
        }

        public static T RequireNext<T>(IEnumerator<T> e)
        {
            if (!e.MoveNext())
                throw new InvalidOperationException();

            return e.Current;
        }

        public static T[] ToArray<T>(IReadOnlyCollection<T> c)
        {
            int count = c.Count, pos = 0;
            T[] a = new T[count];
            foreach (var t in c)
            {
                a[pos++] = t;
            }
            if (pos != count)
                throw new InvalidOperationException();
            return a;
        }

        public static string ToString<T>(IEnumerable<T> c)
        {
            IEnumerator<T> e = c.GetEnumerator();
            if (!e.MoveNext())
                return "[]";

            StringBuilder sb = new StringBuilder("[");
            sb.Append(e.Current);
            while (e.MoveNext())
            {
                sb.Append(", ");
                sb.Append(e.Current);
            }
            sb.Append(']');
            return sb.ToString();
        }

        public static bool TryAdd<K, V>(IDictionary<K, V> d, K k, V v)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return d.TryAdd(k, v);
#else
            if (d.ContainsKey(k))
                return false;

            d.Add(k, v);
            return true;
#endif
        }
    }
}
