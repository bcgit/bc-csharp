namespace Org.BouncyCastle.Runtime.Intrinsics.X86
{
    internal static class Pclmulqdq
    {
#if NETCOREAPP3_0_OR_GREATER
        internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported;
#else
        internal static bool IsEnabled => false;
#endif

        internal static class V256
        {
#if NET10_0_OR_GREATER
            internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.V256.IsSupported;
#else
            internal static bool IsEnabled => false;
#endif
        }

        internal static class V512
        {
#if NET10_0_OR_GREATER
            internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.V512.IsSupported;
#else
            internal static bool IsEnabled => false;
#endif
        }

//        internal static class X64
//        {
//#if NETCOREAPP3_0_OR_GREATER
//            internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.X64.IsSupported;
//#else
//            internal static bool IsEnabled => false;
//#endif
//        }
    }
}
