# stigtools
toolkit to help manage stigs. Rewrite of [zincarla/STIGSupport](https://github.com/zincarla/STIGSupport)

The awesomest command converts SCC output right to a .CKL file.

First, save the whole STIG library using `Save-StigLibrary`

![image](https://user-images.githubusercontent.com/8278033/119815150-88fff580-beeb-11eb-97d7-6d436107cd8e.png)

Then run `Convert-SCC`

```powershell
    $params = @{
        LibraryPath     = "/home/runner/work/stigtools/stigtools/tests/stigs"
        ResultsPath     = "/home/runner/work/stigtools/stigtools/tests/SCC"
        Destination     = "/tmp"
        WarningVariable = "warning"
        WarningAction   = "SilentlyContinue"
    }
    Convert-SCC @params
```

![image](https://user-images.githubusercontent.com/8278033/119814796-1abb3300-beeb-11eb-94d4-0e26d1b13c34.png)

You can also read checklists and work with the data.

```powershell
Read-Checklist -Path /tmp/winserver_U_Windows_Firewall_STIG_V1R7.ckl
```
