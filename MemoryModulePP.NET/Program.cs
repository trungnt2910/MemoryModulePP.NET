using MemoryModule;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

var suffix = Environment.Is64BitProcess ? "64" : "";

using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"MemoryModulePP{suffix}.dll");
using var memoryModulePP = NativeAssembly.Load(stream);

var LdrLoadDllMemoryExW = memoryModulePP.GetDelegate<LdrLoadDllMemoryExWDelegate>("LdrLoadDllMemoryExW");
var LdrUnloadDllMemory = memoryModulePP.GetDelegate<LdrUnloadDllMemoryDelegate>("LdrUnloadDllMemory");

using var secretStream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"Secret{suffix}.dll")!;
using var secretMs = new MemoryStream();
secretStream.CopyTo(secretMs);
var secretBytes = secretMs.ToArray();

const uint LOAD_FLAGS_PASS_IMAGE_CHECK = 0x40000000;

LdrLoadDllMemoryExW(
    out IntPtr secretHandle,
    out _,
    // MemoryModulePP has a weird check that will somehow fail for our binaries.
    LOAD_FLAGS_PASS_IMAGE_CHECK,
    secretBytes,
    // This misleading parameter must always be 0.
    0,
    "secret",
    null
);

NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(),
    (name, asm, path) =>
    {
        if (name == "secret")
        {
            return secretHandle;
        }

        return IntPtr.Zero;
    });

for (int i = 0; i < 10; ++i)
{
    [DllImport("secret")]
    static extern int GetSecret();

    int result = GetSecret();
    Console.WriteLine(result);
    Debug.Assert(Math.Clamp(result, 0, 100) == result);
}

LdrUnloadDllMemory(secretHandle);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate int LdrLoadDllMemoryExWDelegate(
    [Out] out IntPtr BaseAddress,
    [Out] out IntPtr LdrEntry,
    [In] uint dwFlags,
    [In][MarshalAs(UnmanagedType.LPArray)] byte[] BufferAddress,
    [In] UIntPtr BufferSize,
    [In][MarshalAs(UnmanagedType.LPWStr)] string? DllName,
    [In][MarshalAs(UnmanagedType.LPWStr)] string? DllFullName
);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate bool LdrUnloadDllMemoryDelegate([In] IntPtr BaseAddress);
