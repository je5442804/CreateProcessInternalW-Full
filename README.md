# CreateProcessInternalW-Full  
Reimplement CreateProcessInternalW via Windows 10 20H1+ and Windows 11.   
Base on [__NtCreateUserProcess-Post__](https://github.com/je5442804/NtCreateUserProcess-Post)  
  
__Explore Attack Surface and the New Techniques relate to this as far as you can,__  
__or it's useless for you.__  

## Tested on (x64 only)  
Windows 11 24H2 x64 (26252.5000)  **Preview**  
Windows 11 23H2 x64 (22631.3880)  
Windows 11 21H2 x64 (22000.795/22000.1098/22000.2600)  
Windows Server 2022 x64 (20348.2582)  
Windows 10 22H2 x64 (19045.4651)  
Windows 10 21H2 x64 (19044.1826)  

## Example
__CreateProcessInternalW-Full.exe  (ImageName)__  
(1) CreateProcessInternalW-Full.exe dfrgui  
(2) CreateProcessInternalW-Full.exe skype  
(3) CreateProcessInternalW-Full.exe "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe"  (No more)   
(4) CreateProcessInternalW-Full.exe "C:\Program Files (x86)\duowan\yy\YY.exe"  (v9.33.0.1 InvalidHandle 0xc0000008 with Strict Handle Checks)   
(5) CreateProcessInternalW-Full.exe MediaPlayer   
(6) CreateProcessInternalW-Full.exe "\\"C:\Program Files (x86)\cmcm\kdesk\kwallpaper.exe\\" /from:27" lolarg3  
(set argc >= 3 to disable lpAttributeList)  
  
## Build Environment  
Visual Studio 2022  
__Relase x64__  

## Tips
In recent years, Qihoo 360 has made a great defense in "ProcessAttack Protection"  
With the Core Crystal Protection Engine (Intel VT / AMD-V) 360 make the Process Detection Powerful.  
~~It seems that public techniques of Process Injection already be killed, no universal techniques to bypass.~~  
~~(Some uncommon techniques bypass it, but huge limitations...)~~  

Someone tries to use VM Environment spoof or Incompatible Drivers to make a fool of 360,  
which enforce to disable or adjust Core Crystal Engine by 360Safe itself.  
Yeah, there is no way to bypass the Behavior Detection: "I'm just afraid of your detection, shutdown your Core Crystal Engine lol :(".  

This technique isn't good enough, what if I say that:  
at least two universal, undisclosed, different types of technologies (probably work well before Vista or not?) completely bypass Behavior Detection to  
inject Remote Process when Core Crystal Engine is running normally.  
Both of them work well on Windows Vista to Windows 11.  
  
(perhaps it's less related to the repo?)  Ovo?  
(What does it mean that bypass Qihoo 360 Process Inject Detection base on Core Crystal Engine?)  
__OMG! The others' amazingly different research [PoolParty](https://github.com/SafeBreach-Labs/PoolParty) should be respected!__  
  
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
  
(AppCompat ShimEngine Ex)  
40: https://github.com/EricZimmerman/SDB  
41: https://www.alex-ionescu.com/secrets-of-the-application-compatilibity-database-sdb-part-1/  
42: https://www.alex-ionescu.com/secrets-of-the-application-compatilibity-database-sdb-part-2/  
43: https://www.alex-ionescu.com/secrets-of-the-application-compatilibity-database-sdb-part-3/  
44: https://www.alex-ionescu.com/secrets-of-the-application-compatilibity-database-sdb-part-4/  
45: https://ss64.org/viewtopic.php?t=18  
46: https://gist.github.com/riverar/7de4bae1162858b1966e37b335dd24c8  
47: https://github.com/heaths/sdb2xml  
48: https://withinrafael.com/  
49: https://sdb.tools/resources.html  
50: https://reactos.org/wiki/User:Learn_more/Appcompat  
51: https://github.com/vatsan-madhavan/WpfAppCompatQuirks/tree/master  
52: https://github.com/mbevilacqua/appcompatprocessor  
53: https://www.tiraniddo.dev/2019/02/a-brief-history-of-basenamedobjects-on.html  
  
(Console & Pseudo Pty)  
54: https://www.coresecurity.com/core-labs/articles/running-pes-inline-without-console  
55: https://github.com/jfhs/handterm/blob/master/src/handterm.cpp#L2278  
56: https://github.com/adamyg/winxsh/blob/master/rlogind/ConPty.cpp  
57: https://github.com/microsoft/terminal/blob/main/src/server/Entrypoints.cpp  
58: https://learn.microsoft.com/en-us/windows/console/  
59: https://devblogs.microsoft.com/commandline/windows-command-line-introducing-the-windows-pseudo-console-conpty/  ->OpenSSH For Windows  
60: https://github.com/microsoft/terminal/issues/11276  
  
(Attribute List? sxs?)   
61: https://learn.microsoft.com/zh-cn/windows/win32/sbscs/installing-side-by-side-assemblies  
62: https://techcommunity.microsoft.com/t5/msix/are-child-processes-quot-break-away-quot-or-not-by-default/m-p/1671578  
63: https://techcommunity.microsoft.com/t5/msix/msix-breakaway-in-22h2-win-10-11/m-p/4006620  
64: https://big5-sec.github.io/posts/component-filter-mitigation/  
65: https://source.chromium.org/chromium/chromium/src/+/main:sandbox/win/src/startup_information_helper.cc;l=184;drc=af2ce820de3267752a75f21f7d05d674955dd27c?q=PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY&sq=&ss=chromium%2Fchromium%2Fsrc  
  
(I don't know what the RE)  
66: https://dev.to/armsofsorrow/taking-a-look-inside-the-hololens-2-emulator-36e7  
67: https://github.com/gus33000/UUPMediaCreator/issues/189  
68: https://github.com/Empyreal96/W10M_Toolbox  
69: https://github.com/Empyreal96/WP_Common_Tools  
70: https://www.matteomalvica.com/blog/2021/03/10/practical-re-win-solutions-ch3-work-items/  
71: https://bbs.kanxue.com/thread-270131.htm  
72: https://www.mandiant.com/resources/blog/finding-evil-in-windows-ten-compressed-memory-part-one 内存压缩  
