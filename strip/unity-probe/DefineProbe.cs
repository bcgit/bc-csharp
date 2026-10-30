// Drop into any Unity 2021.3 project under Assets/. Logs which compiler defines the BC source's #if guards see.
// Runs in Editor play mode and in player builds (IL2CPP iOS/Android) via RuntimeInitializeOnLoadMethod.
using System.Text;
using UnityEngine;

public static class DefineProbe
{
    [RuntimeInitializeOnLoadMethod]
    private static void Log()
    {
        var sb = new StringBuilder("[DefineProbe] ");
#if NETSTANDARD2_1_OR_GREATER
        sb.Append("NETSTANDARD2_1_OR_GREATER=yes ");
#else
        sb.Append("NETSTANDARD2_1_OR_GREATER=no ");
#endif
#if NETSTANDARD2_1
        sb.Append("NETSTANDARD2_1=yes ");
#else
        sb.Append("NETSTANDARD2_1=no ");
#endif
#if NETCOREAPP2_1_OR_GREATER
        sb.Append("NETCOREAPP2_1_OR_GREATER=yes ");
#else
        sb.Append("NETCOREAPP2_1_OR_GREATER=no ");
#endif
#if NETCOREAPP3_0_OR_GREATER
        sb.Append("NETCOREAPP3_0_OR_GREATER=yes ");
#else
        sb.Append("NETCOREAPP3_0_OR_GREATER=no ");
#endif
#if NET_STANDARD_2_0
        sb.Append("NET_STANDARD_2_0=yes ");
#endif
#if NET_4_6
        sb.Append("NET_4_6=yes ");
#endif
#if ENABLE_IL2CPP
        sb.Append("IL2CPP=yes ");
#endif
        sb.Append("Span=").Append(typeof(System.Span<byte>).Assembly.GetName().Name);
        Debug.Log(sb.ToString());
    }
}
