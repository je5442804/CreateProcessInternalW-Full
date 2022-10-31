# CreateProcessInternalW-Full  
Reimplement CreateProcessInternalW via Windows 10 20H1+  
Base on [__NtCreateUserProcess-Post__](https://github.com/je5442804/NtCreateUserProcess-Post)  
emmmm it should be release in early July. However something happened to me.  
  
__Explorer Attack Surface and the New Techniques relate to this as far as you can,__  
__or it's useless for you.__  

## Tested on (x64 only)  
Windows 11 21H2 x64 (22000.795/22000.1098)  
Windows 10 22H2 x64 (19045.2130)  
Windows 10 21H2 x64 (19044.1826)  

## Example
__CreateProcessInternalW-Full.exe  (ImageName)__  
(1) CreateProcessInternalW-Full.exe dfrgui  
(2) CreateProcessInternalW-Full.exe skype  
(3) CreateProcessInternalW-Full.exe "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe"  

## Build Environment  
Visual Studio 2022  
__Relase x64__  

## Tips
In recent years Qihoo 360 has make a great defense in "ProcessAttack Protection"  
With the Core Crystal Protection Engine (Intel VT / AMD-V) 360 make the Process Detection Powerful.  
It's seem that public techniques of Process Injection already be killed, No universal techniques to bypasss.  
(Some uncommon technique bypass it, but huge limition...)  

Someone try to use VM Environment spoof or Incompatible Drivers to make a fool of 360,  
which enforce to disable or adjust Core Crystal Engine by 360Safe itself.  
Yeah, there is no way to bypass the Behavior Detection: "I'm just afraid of your detect, shutdown your Core Crystal Engine lol :(".  

This technique isn't good enough, what if I say that:  
at least two universal, undisclosed, different types technologies (probably work well before Vista or not?) completely bypass Behavior Detection to  
inject Remote Process when Core Crystal Engine is running normally.  
Both of them work well on Windows Vista to Windows 11.  
  
(perhaps it's less related my repo?)  Ovo?  
(What does it mean that bypass Qihoo 360 Process Inject Detection base on Core Crystal Engine?)  
  
## References && Credits  
Special Thank to MeeSong for his [__Excellent Project__](https://github.com/MeeSong/Reverse-Engineering/tree/master/CreateProcessInternal)  
  
24: https://github.com/MeeSong/Reverse-Engineering/blob/master/CreateProcessInternal  
25: https://github.com/diversenok/NtUtilsLibrary  
26: https://medium.com/@Achilles8284/the-birth-of-a-process-part-2-97c6fb9c42a2  
27: https://www.tiraniddo.dev/2019/09/overview-of-windows-execution-aliases.html  
28: https://www.tiraniddo.dev/2020/02/dll-import-redirection-in-windows-10_8.html  
29: https://www.cyberforum.ru/blogs/172954/blog6136.html  
30: https://docs.microsoft.com/en-us/windows/compatibility/ntvdm-and-16-bit-app-support  
31: http://blog.nsfocus.net/x64-win10-shim/  
32: https://bugs.chromium.org/p/project-zero/issues/detail?id=118  
33: https://blogs.360.cn/post/ntapphelpcachecontrol_vulnerability_anaysis.html  
34: https://chentiangemalc.wordpress.com/2021/11/08/case-of-the-windows-11-notepad-failed-to-launch/  
35: https://docs.microsoft.com/en-us/windows/console/console-handles  
36: https://docs.microsoft.com/en-us/windows/win32/fileio/reparse-points __FILE_FLAG_OPEN_REPARSE_POINT__  
37: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4  
38: https://stackoverflow.com/questions/62474046/how-do-i-find-the-target-of-a-windows-app-execution-alias-in-c-win32-api  
39: https://stackoverflow.com/questions/71697488/follow-hard-links-reparsepoints-to-files-windows-terminal  
