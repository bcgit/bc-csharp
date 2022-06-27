using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Utilities.Collections
{
    public abstract class CollectionUtilities
    {
        public static void AddRange(IList to, IEnumerable range)
        {
            foreach (object o in range)
            {
                to.Add(o);
            }
        }

        public static void CollectMatches<T>(ICollection<T> matches, ISelector<T> selector, params IStore<T>[] stores)
        {
            CollectMatches(matches, selector, stores);
        }

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

        public static V GetValueOrNull<K, V>(IDictionary<K, V> d, K k)
            where V : class
        {
            return d.TryGetValue(k, out var v) ? v : null;
        }

        public static IEnumerable<T> Proxy<T>(IEnumerable<T> e)
        {
            return new EnumerableProxy<T>(e);
        }

        public static IDictionary ReadOnly(IDictionary d)
        {
            return new UnmodifiableDictionaryProxy(d);
        }

        public static IList ReadOnly(IList l)
        {
            return new UnmodifiableListProxy(l);
        }

        public static ISet ReadOnly(ISet s)
        {
            return new UnmodifiableSetProxy(s);
        }

        public static bool Remove<K, V>(IDictionary<K, V> d, K k, out V v)
        {
            if (!d.TryGetValue(k, out v))
                return false;

            d.Remove(k);
            return true;
        }

        public static object RequireNext(IEnumerator e)
        {
            if (!e.MoveNext())
                throw new InvalidOperationException();

            return e.Current;
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
    }
}
