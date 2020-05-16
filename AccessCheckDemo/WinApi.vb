Imports System.Runtime.InteropServices
Imports System.Security.AccessControl

Public Class WinApi

    'See https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
    Public Enum GenericFileRights As UInteger
        FILE_GENERIC_EXECUTE = FileSystemRights.ExecuteFile Or FileSystemRights.ReadPermissions Or FileSystemRights.ReadAttributes Or FileSystemRights.Synchronize
        FILE_GENERIC_READ = FileSystemRights.ReadAttributes Or FileSystemRights.ReadData Or FileSystemRights.ReadExtendedAttributes Or FileSystemRights.ReadPermissions Or FileSystemRights.Synchronize
        FILE_GENERIC_WRITE = FileSystemRights.AppendData Or FileSystemRights.WriteAttributes Or FileSystemRights.WriteData Or FileSystemRights.WriteExtendedAttributes Or FileSystemRights.ReadPermissions Or FileSystemRights.Synchronize
        FILE_GENERIC_ALL = FileSystemRights.FullControl
    End Enum

    <StructLayout(LayoutKind.Sequential)> _
    Public Structure PRIVILEGE_SET
        Public PrivilegeCount As UInteger
        Public Control As UInteger
        Public Privilege As LUID_AND_ATTRIBUTES
    End Structure

    <StructLayout(LayoutKind.Sequential)> _
    Public Structure GENERIC_MAPPING
        Public GenericRead As UInteger
        Public GenericWrite As UInteger
        Public GenericExecute As UInteger
        Public GenericAll As UInteger
    End Structure

    <StructLayout(LayoutKind.Sequential)> _
    Public Structure LUID_AND_ATTRIBUTES
        Public Luid As LUID
        Public Attributes As UInteger
    End Structure

    <StructLayout(LayoutKind.Sequential)> _
    Public Structure LUID
        Public LowPart As UInteger
        Public HighPart As Integer
    End Structure

    'See https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck
    <DllImport("advapi32.dll", EntryPoint:="AccessCheck", SetLastError:=True)> _
    Public Shared Function AccessCheck(ByVal pSecurityDescriptor As Byte(),
                                       ByVal ClientToken As IntPtr,
                                       ByVal DesiredAccess As UInteger,
                                       ByRef GenericMapping As GENERIC_MAPPING,
                                       ByRef PrivilegeSet As PRIVILEGE_SET,
                                       ByRef PrivilegeSetLength As UInteger,
                                       ByRef GrantedAccess As UInteger,
                                       ByRef AccessStatus As Integer) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function



End Class
