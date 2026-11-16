using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Utilities.Collections
{
    /// <summary>Utility methods for working with collections, dictionaries and stores.</summary>
    // TODO[api] Make static
    public abstract class CollectionUtilities
    {
        /// <summary>Add the matches for a selector from each of a set of stores to a collection.</summary>
        /// <param name="matches">The collection to add the matches to.</param>
        /// <param name="selector">The selector to match against.</param>
        /// <param name="stores">The stores to search; null entries are ignored.</param>
        /// <exception cref="ArgumentNullException"><paramref name="matches"/> is null.</exception>
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

        /// <summary>Create a store holding the given contents.</summary>
        /// <param name="contents">The objects to hold in the store.</param>
        /// <returns>A new store.</returns>
        public static IStore<T> CreateStore<T>(IEnumerable<T> contents)
        {
            return new StoreImpl<T>(contents);
        }

        /// <summary>Get the first element of a sequence.</summary>
        /// <param name="e">The sequence, or null.</param>
        /// <returns>The first element, or null if the sequence is null or empty.</returns>
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

        /// <summary>Look up a key in a dictionary, falling back to the key itself.</summary>
        /// <param name="d">The dictionary.</param>
        /// <param name="k">The key.</param>
        /// <returns>The value mapped to the key, or the key if there is no mapping.</returns>
        public static T GetValueOrKey<T>(IDictionary<T, T> d, T k)
        {
            return d.TryGetValue(k, out var v) ? v : k;
        }

        /// <summary>Look up a key in a dictionary, falling back to null.</summary>
        /// <param name="d">The dictionary.</param>
        /// <param name="k">The key.</param>
        /// <returns>The value mapped to the key, or null if there is no mapping.</returns>
        public static V GetValueOrNull<K, V>(IDictionary<K, V> d, K k)
            where V : class
        {
            return d.TryGetValue(k, out var v) ? v : null;
        }

        /// <summary>Determine whether a collection is null or empty.</summary>
        /// <param name="c">The collection, or null.</param>
        /// <returns>true if the collection is null or has no elements, false otherwise.</returns>
        public static bool IsNullOrEmpty<T>(ICollection<T> c)
        {
            return c == null || c.Count < 1;
        }

        /// <summary>
        /// Apply a function to each element of an array or collection, collecting the results in a new array.
        /// </summary>
        /// <param name="ts">The array to map.</param>
        /// <param name="f">The function to apply.</param>
        /// <returns>A new array holding the results, in order.</returns>
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

        /// <summary>
        /// Apply a function to each element of an array or collection, collecting the results in a new array.
        /// </summary>
        /// <param name="c">The collection to map.</param>
        /// <param name="f">The function to apply.</param>
        /// <returns>A new array holding the results, in order.</returns>
        public static TResult[] Map<T, TResult>(IReadOnlyCollection<T> c, Func<T, TResult> f)
        {
            int count = c.Count, pos = 0;
            var result = new TResult[count];
            foreach (var t in c)
            {
                result[pos++] = f(t);
            }
            if (pos != count)
                throw new InvalidOperationException();
            return result;
        }

        /// <summary>Wrap a sequence in a proxy that hides the type of the underlying sequence.</summary>
        /// <param name="e">The sequence to wrap.</param>
        /// <returns>The proxy.</returns>
        public static IEnumerable<T> Proxy<T>(IEnumerable<T> e)
        {
            return new EnumerableProxy<T>(e);
        }

        /// <summary>Wrap a collection in a read-only view.</summary>
        /// <param name="c">The collection to wrap.</param>
        /// <returns>A read-only view of the argument.</returns>
        public static ICollection<T> ReadOnly<T>(ICollection<T> c)
        {
            return new ReadOnlyCollectionProxy<T>(c);
        }

        /// <summary>Wrap a collection in a read-only view.</summary>
        /// <param name="d">The dictionary to wrap.</param>
        /// <returns>A read-only view of the argument.</returns>
        public static IDictionary<K, V> ReadOnly<K, V>(IDictionary<K, V> d)
        {
            return new ReadOnlyDictionaryProxy<K, V>(d);
        }

        /// <summary>Wrap a collection in a read-only view.</summary>
        /// <param name="l">The list to wrap.</param>
        /// <returns>A read-only view of the argument.</returns>
        public static IList<T> ReadOnly<T>(IList<T> l)
        {
            return new ReadOnlyListProxy<T>(l);
        }

#if NETCOREAPP1_0_OR_GREATER || NET40_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        /// <summary>Wrap a collection in a read-only view.</summary>
        /// <param name="s">The set to wrap.</param>
        /// <returns>A read-only view of the argument.</returns>
        public static ISet<T> ReadOnly<T>(ISet<T> s)
        {
            return new ReadOnlySetProxy<T>(s);
        }
#endif

        /// <summary>Remove a key from a dictionary and return the value that was mapped to it.</summary>
        /// <param name="d">The dictionary.</param>
        /// <param name="k">The key to remove.</param>
        /// <param name="v">On success, the value that was mapped to the key.</param>
        /// <returns>true if the key was present and has been removed, false otherwise.</returns>
        public static bool Remove<K, V>(IDictionary<K, V> d, K k, out V v)
        {
            if (!d.TryGetValue(k, out v))
                return false;

            if (!d.Remove(k))
                throw new InvalidOperationException();

            return true;
        }

        /// <summary>Advance an enumerator and return the next element, which must exist.</summary>
        /// <param name="e">The enumerator.</param>
        /// <returns>The next element.</returns>
        /// <exception cref="InvalidOperationException">There is no next element.</exception>
        public static T RequireNext<T>(IEnumerator<T> e)
        {
            if (!e.MoveNext())
                throw new InvalidOperationException();

            return e.Current;
        }

        /// <summary>Project each element of a sequence into a new form.</summary>
        /// <param name="source">The sequence.</param>
        /// <param name="selector">The projection to apply to each element.</param>
        /// <returns>A sequence of the projected elements.</returns>
        // TODO[api] Make extension method
        public static IEnumerable<TResult> Select<TSource, TResult>(IEnumerable<TSource> source,
            Func<TSource, TResult> selector)
        {
            foreach (var element in source)
            {
                yield return selector(element);
            }
        }

        // TODO[api] Make public (currently could conflict with overload)
        internal static T[] ToArray<T>(ICollection<T> c)
        {
            T[] a = new T[c.Count];
            c.CopyTo(a, 0);
            return a;
        }

        /// <summary>Copy the elements of a collection to a new array.</summary>
        /// <param name="c">The collection.</param>
        /// <returns>A new array holding the elements, in enumeration order.</returns>
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

        /// <summary>Format the elements of a sequence as a comma-separated list enclosed in square brackets.</summary>
        /// <param name="c">The sequence.</param>
        /// <returns>The string representation of the sequence.</returns>
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

        /// <summary>Add a key and value to a dictionary if the key is not already present.</summary>
        /// <param name="d">The dictionary.</param>
        /// <param name="k">The key.</param>
        /// <param name="v">The value.</param>
        /// <returns>true if the entry was added, false if the key was already present.</returns>
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

        /// <summary>Filter a sequence, keeping the elements that satisfy a predicate.</summary>
        /// <param name="source">The sequence.</param>
        /// <param name="predicate">The condition each element is tested against.</param>
        /// <returns>A sequence of the elements that satisfy the predicate.</returns>
        // TODO[api] Make extension method
        public static IEnumerable<T> Where<T>(IEnumerable<T> source, Func<T, bool> predicate)
        {
            foreach (var element in source)
            {
                if (predicate(element))
                {
                    yield return element;
                }
            }
        }
    }
}
