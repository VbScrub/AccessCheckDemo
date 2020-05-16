Imports System.Security.Principal
Imports System.Security.AccessControl
Imports System.Runtime.InteropServices

Public Class AccessChecker

    Private Shared GenericFileRightsMap As New WinApi.GENERIC_MAPPING With {.GenericAll = WinApi.GenericFileRights.FILE_GENERIC_ALL,
                                                                            .GenericExecute = WinApi.GenericFileRights.FILE_GENERIC_EXECUTE,
                                                                            .GenericRead = WinApi.GenericFileRights.FILE_GENERIC_READ,
                                                                            .GenericWrite = WinApi.GenericFileRights.FILE_GENERIC_WRITE}


    ''' <summary>
    ''' Checks to see if a user has permission to perform a certain action on a file
    ''' </summary>
    ''' <param name="FilePath">The file to check permissions on</param>
    ''' <param name="Permission">The action we want to see if this user is allowed to perform</param>
    ''' <param name="User">The user we want to check can perform the action on this file. The calling thread must be impersonating this user</param>
    Public Shared Function CheckFileAccess(FilePath As String, Permission As FileSystemRights, User As WindowsIdentity)
        Dim AclBytes() As Byte = IO.File.GetAccessControl(FilePath, AccessControlSections.Access Or AccessControlSections.Group Or AccessControlSections.Owner).GetSecurityDescriptorBinaryForm()
        Dim Privs As WinApi.PRIVILEGE_SET
        Dim GenericMap As WinApi.GENERIC_MAPPING = GenericFileRightsMap
        Dim GrantedRights As UInteger
        Dim Status As UInteger
        Dim Result = WinApi.AccessCheck(AclBytes, User.Token, Permission, GenericMap, Privs, Marshal.SizeOf(Privs), GrantedRights, Status)
        If Not Result Then
            Throw New ComponentModel.Win32Exception
        End If
        Return Status = 1
    End Function

End Class
