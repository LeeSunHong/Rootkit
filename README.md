# rootkit
Process hiding through ntdll.ZwQuerySystemInformation hook<br>
ZwQuerySystemInformation function show process list. so before you use this code, you should check the function structure.<br>
[ZwQuerySystemInformation](https://msdn.microsoft.com/ko-kr/library/windows/desktop/ms725506(v=vs.85).aspx)<br>

After upgraded to window7, we can load only signed driver on kernel.<br>
So, The way used here is ntdll.ZwQuerySystemInformation hook on user level and then disconnect the link from the process linked list.

<h3>how to inject dll to all of the proecss</h3>
I used CreateToolhelp32Snapshot api and I could got pids from process list.<br>
When i got a pid, i injected to process that has pid.
There is 5 step for dll injection<br>
1. You have to get a handle with the pid.<br>
2. You need to free up memory space for dll inserts.<br>
3. Insert the rootkit dll string into the allocated memory space using WriteProcessMemory.<br>
4. You can get a LoadLibraryA address using GetProcAddress API.<br>
5. Load the dll through LoadLibraryA using CreateRemoteThread.<br><br>

I'm current korean university student. So, there may be incorrect grammar sentences. And there is also a lack of explanation.<br>
If you have any problems or any question, reply to me your opinion. Thank you! 
