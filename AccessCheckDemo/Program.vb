Imports System.Security.Principal
Imports System.Security.AccessControl

Module Program

    Sub Main()

        'We have to use impersonation even for our own user account otherwise AccessCheck fails
        Using Impersonation As WindowsImpersonationContext = WindowsIdentity.GetCurrent.Impersonate

            'Check to see if we have permission to Write to the file C:\temp.txt
            Dim WriteAllowed As Boolean = AccessChecker.CheckFileAccess("C:\temp.txt", FileSystemRights.Write, WindowsIdentity.GetCurrent)
            Console.WriteLine("Allowed to write = " & WriteAllowed)

            'Check to see if we have permission to delete the file C:\Test\temp.txt
            Dim DeleteAllowed As Boolean = AccessChecker.CheckFileAccess("C:\Test\temp.txt", FileSystemRights.Delete, WindowsIdentity.GetCurrent)
            Console.WriteLine("Allowed to delete = " & DeleteAllowed)
        End Using

        Console.ReadLine()
    End Sub

End Module
